from collections import deque
import logging
import threading

import tornado.concurrent
import tornado.httpclient
import tornado.httpserver
import tornado.web


logger = logging.getLogger(__name__)


class UpstreamConnection(object):
    def __init__(self):
        self._lock = threading.RLock()
        self._completed = False
        self._completed_fut = tornado.concurrent.Future()
        self._queue = deque()
        self._writer_ready_fut = tornado.concurrent.Future()

    def body_producer(self, write):
        self._write = write
        self._writer_ready_fut.set_result(None)
        return self._completed_fut

    @property
    def _is_completed(self):
        with self._lock:
            return self._completed and not self._queue

    def _write_queued_data(self, fut):
        if self._is_completed:
            self._completed_fut.set_result(None)
            return

        with self._lock:
            data = self._queue.popleft()

        self._write(data)

    def data_received(self, data):
        with self._lock:
            self._queue.append(data)

        self._writer_ready_fut.add_done_callback(self._write_queued_data)

    def on_finish(self):
        self._completed = True
        self._writer_ready_fut.add_done_callback(self._write_queued_data)


def noop(*args, **kwargs):
    return None


def register_response_handler(url, fut):
    def display_http_response(fut):
        try:
            r = fut.result()
            summary = r.code
        except tornado.httpclient.HTTPError as e:
            summary = str(e)

        logger.info("%s: %s", url, summary)

    fut.add_done_callback(display_http_response)


@tornado.web.stream_request_body
class PoolingHandler(tornado.web.RequestHandler):
    BODY_BEARING_METHODS = set(['PATCH', 'POST', 'PUT'])

    def initialize(self, get_upstreams=None, **kwargs):
        self.get_upstreams = get_upstreams
        self._connections = None

    def handle_request(self):
        logger.info('Received request for %s', self.request.path)

        self._connections = []
        upstreams = self.get_upstreams(self.request)

        for host in upstreams:
            headers = self.request.headers.copy()
            headers['Host'] = host.split(':')[0]
            url = '{r.protocol}://{host}{r.uri}'.format(
                r=self.request, host=host)

            if self.request.method in self.BODY_BEARING_METHODS:
                connection = UpstreamConnection()
                body_producer = connection.body_producer
                self._connections.append(connection)
            else:
                body_producer = None

            upstream_request = tornado.httpclient.HTTPRequest(
                url=url,
                method=self.request.method,
                headers=headers,
                body_producer=body_producer,
                follow_redirects=False,
                header_callback=noop,
                streaming_callback=noop,
                validate_cert=True,
            )
            client = tornado.httpclient.AsyncHTTPClient()
            fut = client.fetch(upstream_request)
            register_response_handler(url, fut)

        self.write("OK")

    def data_received(self, data):
        if self._connections is None:
            self.handle_request()
        for connection in self._connections:
            connection.data_received(data)

    def on_finish(self):
        for connection in self._connections:
            connection.on_finish()

    delete = handle_request
    get = handle_request
    head = handle_request
    options = handle_request

    # PATCH, POST, and PUT are received via data_received, but we still
    # need the methods defined to keep tornado from complaining
    patch = noop
    post = noop
    put = noop
