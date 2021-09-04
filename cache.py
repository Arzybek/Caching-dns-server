import time
import codecs
import struct

NAME_OFFSET = b'\xc0\x0c'
PADDING = '11'


def get_cur_time():
    return int(time.time())


def set_padding(n):
    return (8 - len(n)) * '0' + n


def get_qname(record, packet=None):
    index, qname = 0, ''
    try:
        while True:
            if record[index] == 0:
                break
            size = record[index]
            if set_padding(bin(size)[2:])[:2] == PADDING:
                offset = codecs.encode(record[index:index + 2], 'hex').decode()
                offset = int(bin(int(offset, 16))[4:], 2)
                index, record = offset, packet
                continue
            index += 1
            for i in range(index, index + size):
                qname += chr(record[i])
            qname += '.'
            index += size
    except Exception:
        return ''
    return qname


class Cache:
    def __init__(self):
        self.cache = {}
        self.outdate_time = 10
        self.used_qtypes = set()

    def push(self, qname, qtype, question, packet):
        if self.contains(qname, qtype):
            return
        if qname not in self.cache:
            self.cache[qname] = {}
        self.used_qtypes.add(qtype)
        entity = CachedEntity(packet, qtype, question)
        self.cache[qname][qtype] = entity
        return entity.inner_qnames

    def contains(self, qname, qtype):
        return qname in self.cache and qtype in self.cache[qname]

    def get(self, qname, qtype, id):
        answer = b''
        is_outdated = False
        value = self.cache[qname][qtype]

        for field in value.sections:
            cur_time = get_cur_time()
            new_ttl = field.start_time + field.ttl - cur_time
            if new_ttl < self.outdate_time:
                is_outdated = True
                break
            field.set_ttl(new_ttl)
            field.start_time = cur_time

            answer += field.section
        if is_outdated:
            del value
            return None
        return self.process_head(value.head, id) + value.question + answer + value.additional

    def process_head(self, head, id):
        return id + head[2:]


class InnerEntity:
    def __init__(self, ttl, start_time, section):
        self.ttl = ttl
        self.start_time = start_time
        self.section = section

    def set_ttl(self, new_ttl):
        self.ttl = new_ttl
        self.section = self.section[:6] + struct.pack('>I', new_ttl) + self.section[10:]


class CachedEntity:
    def __init__(self, packet, qtype, question):
        self.question = question
        self.qtype = qtype

        self.raw_packet = packet
        self.sections = []
        self.additional = b''
        self.head = b''

        self.inner_qnames = []

        self.process_packet(packet)

    def get_inner(self):
        return self.inner_qnames

    def process_packet(self, packet):
        self.head = packet[:12]
        spacket = packet[12:]
        sections = self.parse_sections(self.head, spacket)

        for section in sections:
            self.sections.append(InnerEntity(self.get_raw_ttl(section), get_cur_time(), section))

    def parse_sections(self, head, packet):
        spacket = head + packet
        question, packet = self.split_packet(packet, packet.find(b'\x00') + 5)
        sections = []

        while len(packet) > 1:
            name, packet = self.split_packet(packet, packet.find(b'\x00'))
            info, packet = self.split_packet(packet, 8)
            rlength, packet = self.split_packet(packet, 2)
            rdata, packet = self.split_packet(packet, struct.unpack('>H', rlength)[0])

            self.process_rdata(info, rdata, spacket)

            section = name + info + rlength + rdata
            sections.append(section)
        return sections

    def process_rdata(self, info, rdata, packet):
        if self.qtype not in [15, 2]:
            return
        offset = codecs.encode(rdata[-2:], 'hex').decode()
        if offset is not '':
            qname = self.get_qname(rdata, packet)
            self.inner_qnames.append(qname)

    def get_qname(self, rdata, packet):
        ndata = rdata[2:] if self.qtype != 2 else rdata
        return get_qname(ndata, packet)

    def split_packet(self, packet, index):
        data = packet[:index]
        return data, packet[index:]

    def get_raw_ttl(self, section):
        ttl = section[6:10]
        tm = struct.unpack('>I', ttl)[0]
        return tm