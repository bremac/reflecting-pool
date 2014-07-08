import base64
import glob
import os
import random
import socket
from SocketServer import BaseRequestHandler, ThreadingTCPServer
import sys
import threading


CHUNK_LEN = 8192
NUM_REQUESTS = 10
NULL_PORT = 9000
RECORDING_PORT = 9001
REQUEST_ID_LEN = 40

RECEIVED_DIR = "received"
SENT_DIR = "sent"

MIN_REQUEST_LEN = REQUEST_ID_LEN
MAX_REQUEST_LEN = 10 * 1024 * 1024


class CountedRequestHandler(BaseRequestHandler):
    lock = threading.Lock()
    num_requests_handled = 0

    def increment_and_maybe_shutdown(self, sigil='!'):
        with self.lock:
            self.__class__.num_requests_handled += 1
            sys.stderr.write('{}{},'.format(sigil, self.num_requests_handled))
            if self.num_requests_handled == NUM_REQUESTS:
                self.server.server_close()


class NullRequestHandler(CountedRequestHandler):
    def handle(self):
        received_data = True

        while received_data:
            received_data = bool(self.request.recv(CHUNK_LEN))

        self.increment_and_maybe_shutdown(sigil='-')
        self.request.shutdown(socket.SHUT_WR)


class RecordingRequestHandler(CountedRequestHandler):
    def handle(self):
        request_id = self.request.recv(REQUEST_ID_LEN)

        if len(request_id) != REQUEST_ID_LEN:
            return

        filename = base64.urlsafe_b64encode(request_id)

        with open(os.path.join(RECEIVED_DIR, filename), 'wb') as f:
            chunk = request_id + self.request.recv(CHUNK_LEN)

            while chunk:
                f.write(chunk)
                chunk = self.request.recv(CHUNK_LEN)

        self.increment_and_maybe_shutdown(sigil='+')
        self.request.shutdown(socket.SHUT_WR)


class ReusableTcpServer(ThreadingTCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    socket_type = socket.SOCK_STREAM


def run_null_server():
    server = ReusableTcpServer(('', NULL_PORT), NullRequestHandler)
    try:
        server.serve_forever()
    except socket.error:
        pass


def run_recording_server():
    server = ReusableTcpServer(('', RECORDING_PORT), RecordingRequestHandler)
    try:
        server.serve_forever()
    except socket.error:
        pass


def run_client(filename):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', NULL_PORT))

    with open(os.path.join(SENT_DIR, filename), 'rb') as f:
        chunk = f.read(8192)

        while chunk:
            s.sendall(chunk)
            chunk = f.read(8192)

    s.shutdown(socket.SHUT_WR)
    s.close()


def generate_request_files():
    filenames = []

    sys.stderr.write('Generating request data: ')

    for i in range(NUM_REQUESTS):
        filename = str(i)
        length = random.randint(MIN_REQUEST_LEN, MAX_REQUEST_LEN)

        with open(os.path.join(SENT_DIR, filename), 'wb') as out_file,\
             open('/dev/urandom', 'rb') as in_file:
            while length > 0:
                chunk_length = min(length, CHUNK_LEN)
                chunk = in_file.read(chunk_length)
                out_file.write(chunk)
                length -= chunk_length

        sys.stderr.write('.')
        filenames.append(filename)

    sys.stderr.write('\n')

    return filenames


def make_empty_directory(dirname):
    try:
        for filename in glob.glob("{}/*".format(dirname)):
            os.remove(filename)
        os.rmdir(dirname)
    except:
        pass

    os.mkdir(dirname)


if __name__ == '__main__':
    make_empty_directory(RECEIVED_DIR)
    make_empty_directory(SENT_DIR)

    threads = []

    filenames = generate_request_files()
    threads.append(threading.Thread(target=run_null_server))
    threads.append(threading.Thread(target=run_recording_server))

    for filename in filenames:
        threads.append(threading.Thread(target=run_client, args=(filename,)))

    for thread in threads:
        thread.daemon = True
        thread.start()

    for thread in threads:
        thread.join()

    sys.stderr.write('\n')
