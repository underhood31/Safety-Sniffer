import struct
import textwrap



def process_tcp_packet(data):
    """
    Unpacks TCP segment
    """
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',data[:14])
    offset=(offset_reserved_flags>12)*4
    #what are tcp flags ????
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = data[offset:]
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def process_udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def process_icmp_packet(data):
    """
    Processes ICMP packet
    """
    icmp_type, code, checksum=struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]