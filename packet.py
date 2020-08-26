
import struct

def ipv4_packet(data):
    """
    Unpacks IPv4 packet

    @args - 14 bytes cropped Cropped data
    
    @return - ttl, proto, src_addr, target_addr, actual data
    """
    version_header_len=data[0]
    version=version_header_len>>4
    header_len=version_header_len^(version<<4)

    ttl, proto, src_addr, target_addr=struct.unpack("! 8x B B 2x 4s 4s", data[ : 20])

    return version, header_len, ttl, proto, get_ipv4(src_addr), get_ipv4(target_addr), data[header_len:]

def get_ipv4(unprocessed):
    """
    Returns properly fomatted IP4 address
    """
    return '.'.join(map(str,unprocessed))


