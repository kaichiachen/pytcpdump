import struct, re
from utils.utils import *

def parse_http(data):

    http_packet = {}
    nodes = data.split(b'\r\n')
    method = re.findall(b"GET|POST|PUT|DELETE", data)[0]
    header_re = re.compile(b"(.*[^=]): (.*)")
    paras = re.findall(b"[^&?]*?=[^&$\s?]*", data)
    header_list = list(filter(header_re.match, nodes))

    http_packet['METHODS'] = method
    http_packet['header'] = header_list
    http_packet['parameters'] = paras

    return http_packet

def parse_tcp(data):
    tcp_header = data[:TCP_LENGTH]

    src_port, dest_port, seq, ack_num, offset, flags, window, checksum, urgent_ptr= struct.unpack('!HHLLBBHHH' , tcp_header)
    reserved = offset & 0xF
    tcpip_length = offset >> 4

    packet = {}
    packet['SRC_PORT'] = src_port
    packet['DEST_PORT'] = dest_port
    packet['SEQ'] = seq
    packet['ACK_NUM'] = ack_num
    flags_arr = []
    flags_arr.append('CWR') if (flags >> 7) & 1 else flags_arr.append('_')
    flags_arr.append('ECE') if (flags >> 6) & 1 else flags_arr.append('_')
    flags_arr.append('URG') if (flags >> 5) & 1 else flags_arr.append('_')
    flags_arr.append('ACK') if (flags >> 4) & 1 else flags_arr.append('_')
    flags_arr.append('PSH') if (flags >> 3) & 1 else flags_arr.append('_')
    flags_arr.append('RST') if (flags >> 2) & 1 else flags_arr.append('_')
    flags_arr.append('SYN') if (flags >> 1) & 1 else flags_arr.append('_')
    flags_arr.append('FIN') if (flags >> 0) & 1 else flags_arr.append('_')
    packet['Flags'] = ','.join(flags_arr)
    packet['RESERVE'] = reserved
    packet['TCP_LENGTH'] = tcpip_length
    packet['WINDOW'] = window
    packet['CHECKSUM'] = checksum
    packet['PTR'] = urgent_ptr
    if b'HTTP' in data:
        packet['HTTP'] = parse_http(data[TCP_LENGTH+tcpip_length:])
    return packet

def handle_tcp(data, output):
    packet = parse_tcp(data)
    return packet
