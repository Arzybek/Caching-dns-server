import abc
import socket
import queue
from concurrent.futures import ThreadPoolExecutor

BUFFER_SIZE = 1024
LOCAL_ADDR = ('127.0.0.1', 53)
CLOSE = "close"


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(LOCAL_ADDR)
    return sock.getsockname()[0]  


class BaseServer:
    def __init__(self, port):
        self.port = port

        self.sock = self.make_socket(1000000)
        self.sock.bind(('', self.port))
        self.max_workers = 5
        self.answer_queue = queue.Queue()
        self.FLAG = False
        print('Server is configurated')

    @abc.abstractmethod
    def client_req_handler(self, addr, packet):
        pass

    def shutdown(self):
        print('Closed')

    def make_socket(self, timeout=2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        return sock

    def run(self):
        pool = ThreadPoolExecutor(self.max_workers)

        print('Server is running on {}:{}'.format(get_local_ip(), self.port))

        try:
            while True:
                try:
                    resp, addr = self.sock.recvfrom(BUFFER_SIZE)
                except socket.error:
                    pass
                if self.FLAG:
                    raise KeyboardInterrupt
                self.process_packet(resp, addr)
        except KeyboardInterrupt:
            self.shutdown()

    def process_packet(self, packet, addr):
        pack_type = self.get_packet_type(packet)

        if pack_type == 0:
            self.client_req_handler(addr, packet)
        else:
            raise Exception('Invalid packet')

    def get_packet_type(self, packet):
        return packet[3] >> 7
