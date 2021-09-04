import argparse
import binascii
import socket
import sys
from threading import Thread

from IPy import IP
from dns_server import DNS

MIN_PORT = 0
MAX_PORT = 65536


def createParser():
    parser = argparse.ArgumentParser(description="Кэширующий DNS server")
    parser.add_argument('-p', '--port', required=True, type=int, help='Порт')
    parser.add_argument('-f', '--forwarder', required=True, help='Ip:Port forward сервера. Например: 8.8.8.8:53')
    return parser


def make_req(port, DNS):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    message = "AA AA 01 00 00 01 00 00 00 00 00 00 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 00 01 00 01"
    message = message.replace(" ", "").replace("\n", "")
    sock.sendto(binascii.unhexlify(message), ('127.0.0.1', 53))
    DNS.FLAG = True


def main():
    parser = createParser()
    args = parser.parse_args()
    port = args.port
    forwarder = args.forwarder

    if ':' in forwarder:
        forwarder = tuple(forwarder.split(':'))
    else:
        forwarder = (forwarder, 53)
    forwarder = (socket.gethostbyname(forwarder[0]), int(forwarder[1]))
    try:
        IP(forwarder[0])
    except ValueError:
        print('Invalid forwarders IP')
        sys.exit()

    try:
        port = int(port)
        if port < MIN_PORT or port > MAX_PORT:
            print('Incorrect port')
            sys.exit()
    except ValueError:
        print('Invalid port')
        sys.exit()

    dns_server = DNS(port, forwarder)
    var = Thread(target=dns_server.run)
    var.start()

    while True:
        n = input()
        if n == "close":
            make_req(dns_server.port, dns_server)


if __name__ == '__main__':
    main()
