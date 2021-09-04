import os
import socket
import datetime
import struct
from random import randint

from threading import Lock, Thread
from server import BaseServer, BUFFER_SIZE
from cache import Cache, get_qname, set_padding

TYPES = {
    1: 'A', 2: 'NS', 28: 'AAAA', 15: 'MX', 12: "PTR"
}

MIN_VALUE = 50000
MAX_VALUE = 65535
PADDING = '11'


class DNS(BaseServer):

    def __init__(self, port, forwarder):
        super(DNS, self).__init__(port)
        self.forwarder = forwarder
        self.forwarder_corrupted = False

        self.init_cache()
        self.lock = Lock()

    def init_cache(self):
        f = open("cache.txt", 'r')
        s = f.readlines()
        if len(s) != 0:
            s = s[:-1]
            self.cache = Cache()
            for line in s:
                try:
                    line = line.strip()
                    if len(line) == 0:
                        continue
                    str_b = bytes.fromhex(line)
                    question, qname, qtype = self.get_question(str_b)
                    self.cache.push(qname, qtype, question, str_b)
                except Exception:
                    print(line)
        else:
            self.cache = Cache()

    def client_req_handler(self, addr, packet):
        self.forwarder_corrupted = False
        self.client = addr

        question, qname, qtype = self.get_question(packet)
        from_cache = False
        apacket = b''
        if self.cache.contains(qname, qtype):
            with self.lock:
                apacket, from_cache = self.cache.get(qname, qtype, packet[:2]), True
        elif qtype in TYPES.keys():
            fl = qname.find("1.0.0.127.in-addr.arpa")
            if qtype == 12 and fl != -1:
                apacket = self.make_request2forwarder(packet)
                self.cache.push(qname, qtype, question, apacket)
            else:
                new_pack = self.copy_pack(packet, b'\x00\x02')
                try:
                    response = self.make_request2forwarder(new_pack)
                    head = response[:12]
                    pck_tmp = response[12:]
                    sections = self.parse_sections(head, pck_tmp)

                    rdata = sections[0]

                    auth_server = rdata[0]
                    sock_tmp = self.make_socket()
                    sock_tmp.sendto(packet, (auth_server, 53))
                    apacket, naddr = sock_tmp.recvfrom(BUFFER_SIZE)
                    self.cache.push(qname, qtype, question, apacket)
                    if qtype != 2:
                        n_question, n_qname, n_qtype = self.get_question(new_pack)
                        sock_tmp.sendto(new_pack, (auth_server, 53))
                        npacket, naddr = sock_tmp.recvfrom(BUFFER_SIZE)
                        inner_names = self.cache.push(n_qname, n_qtype, n_question, npacket)
                        Thread(target=self.func, args=(inner_names, auth_server)).start()
                except Exception:
                    self.forwarder_corrupted = True
                    self.return_server_resp(self.make_error_packet(packet))
        else:
            apacket = self.make_request2forwarder(packet)
        if not self.forwarder_corrupted:
            print(datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S"), end=" ")
            print("-- [*] {} {} {}".format(addr[0], TYPES[qtype], qname), end=" ")
            print('cache' if from_cache else 'forwarder')
            self.return_server_resp(apacket)

    def func(self, inner_names, auth_server):
        sock_tmp = self.make_socket()
        secs = inner_names
        if len(secs) > 0:
            for name in secs:
                if name != '':
                    ns_packet = self.create_dns_request(name, 1)
                    sock_tmp.sendto(ns_packet, (auth_server, 53))
                    nspacket, nsaddr = sock_tmp.recvfrom(BUFFER_SIZE)
                    ns_question, ns_qname, ns_qtype = self.get_question(ns_packet)
                    self.cache.push(ns_qname, ns_qtype, ns_question, nspacket)
        sock_tmp.close()

    def make_request2forwarder(self, packet):
        if packet is None:
            return
        with self.lock:
            sock = self.make_socket()
            npacket = b""
            try:
                sock.sendto(packet, self.forwarder)
                npacket, addr = sock.recvfrom(BUFFER_SIZE)
            except socket.error:
                self.return_server_resp(self.make_error_packet(packet))
            finally:
                sock.close()
            return npacket

    def parse_sections(self, head, packet):
        spacket = head + packet
        question, packet = self.split_packet(packet, packet.find(b'\x00') + 5)
        sections = []
        while len(packet) > 1:
            name, packet = self.split_packet(packet, packet.find(b'\x00'))
            info, packet = self.split_packet(packet, 8)
            rlength, packet = self.split_packet(packet, 2)
            rdata, packet = self.split_packet(packet, struct.unpack('>H', rlength)[0])
            name_1 = get_qname(rdata, spacket)
            section = [name_1, name, info, rlength, rdata, name + info + rlength + rdata]
            sections.append(section)
        return sections

    def split_packet(self, packet, index):
        data = packet[:index]
        return data, packet[index:]

    def copy_pack(self, packet, qtype):
        spacket = packet[12:]
        question_section = spacket[:spacket.find(b'\x00') + 5]
        question = spacket[:spacket.find(b'\x00')]
        qname = get_qname(question_section)
        ind = question_section.find(b'\x00')
        qclass = question_section[ind + 3:][:2]
        other = question_section[ind + 5:]
        new_pack = packet[:12] + question + b'\x00' + qtype + qclass + other
        return new_pack

    def get_question(self, packet):
        spacket = packet[12:]
        question = spacket[:spacket.find(b'\x00') + 5]
        qname = get_qname(question)
        ind = question.find(b'\x00')
        qtype = struct.unpack('>H', question[ind + 1:][:2])[0]
        return question, qname, qtype

    def return_server_resp(self, packet):
        self.sock.sendto(packet, self.client)

    def make_error_packet(self, packet):
        flags = '1' + set_padding(bin(packet[2])[2:])[1:]
        rcode = set_padding(bin(packet[3])[2:])

        return packet[:2] + struct.pack('>H', int(flags + rcode[:4] + '0010', 2)) + packet[4:]

    def shutdown(self):
        f = open('cache.txt', 'w')
        s = []
        for key, value in self.cache.cache.items():
            for k, v in value.items():
                s.append(v.raw_packet.hex())
        for line in s:
            f.write(line)
            f.write("\n")
        f.close()
        print("Closed and cached")
        os._exit(0)

    def create_dns_request(self, name, type):
        with self.lock:
            name = name.encode()

            id = struct.pack('>H', randint(MIN_VALUE, MAX_VALUE))
            flags = b'\x01\x20'
            question = b'\x00\x01'
            answer = b'\x00\x00'
            authority = b'\x00\x00'
            addit = b'\x00\x00'

            qname = b''
            for part in name.split(b'.'):
                qname += struct.pack('B', len(part)) + part
            qtype = struct.pack('>H', type)
            qclass = b'\x00\x01'
            return id + flags + question + answer + authority + addit + qname + qtype + qclass
