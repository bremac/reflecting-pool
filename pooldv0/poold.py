from collections import deque
import os
import sys
import threading

import tornado.concurrent
import tornado.httpclient
import tornado.httpserver
import tornado.ioloop
import tornado.web


# XXX: Timeouts?

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

    def _write_queued_data(self):
        if self._is_completed:
            self._completed_fut.set_result(None)
            return

        with self._lock:
            data = self._queue.popleft()

        self._write(data)

    def data_received(self, data):
        with self._lock:
            self._queue.extend(data)

        self._writer_ready_fut.add_done_callback(self._write_queued_data)

    def on_finish(self):
        self._completed = True
        self._writer_ready_fut.add_done_callback(self._write_queued_data)


def noop(*args, **kwargs):
    return None


@tornado.web.stream_request_body
class PoolingHandler(tornado.web.RequestHandler):
    BODY_BEARING_METHODS = set(['PATCH', 'POST', 'PUT'])

    def initialize(self, get_upstreams=None, **kwargs):
        self.get_upstreams = get_upstreams

    def handle_request(self):
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
            client.fetch(upstream_request)

        self.write("OK")

    def data_received(self, data):
        for connection in self._connections:
            connection.data_received(data)

    def on_finish(self):
        for connection in self._connections:
            connection.on_finish()

    delete = handle_request
    get = handle_request
    head = handle_request
    options = handle_request
    patch = handle_request
    post = handle_request
    put = handle_request


def usage():
    print 'Usage: poold.py [FILENAME]'
    print
    print 'Run poold with the settings from the python file FILENAME. If FILENAME is not'
    print 'specified, settings will be loaded from /etc/poold.conf.py.'
    print
    print 'The settings file must define a get_upstreams function that takes a'
    print 'tornado.httputil.HTTPServerRequest and returns a list of strings specifying'
    print 'upstream hosts to forward the request to. Each hostname may be specified in the'
    print 'form HOSTNAME:PORT, or HOSTNAME.'
    print
    print 'The settings file may also define POOLD_PORT to be an integer value indicating'
    print 'which port to listen on.'
    print

    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) > 2:
        usage()
    elif len(sys.argv) == 2 and sys.argv[1] in ('-h', '--help'):
        usage()
    elif len(sys.argv) == 2:
        filename = sys.argv[1]
    else:
        filename = '/etc/poold.conf.py'

    settings = {}

    if not os.access(filename, os.R_OK):
        print 'Failed to read settings from {}'.format(filename)
        sys.exit(1)

    execfile(filename, settings, settings)

    if 'get_upstreams' not in settings:
        print 'Error: get_upstreams function was not found in settings'
        sys.exit(1)

    port = settings.get('POOLD_PORT', 8000)
    print 'Listening for connections on port {}'.format(port)

    application = tornado.web.Application([
        tornado.web.url(r"/.*", PoolingHandler, settings),
    ], autoreload=True, serve_traceback=True)

    application.listen(port)
    tornado.ioloop.IOLoop.instance().start()
