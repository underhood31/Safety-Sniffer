import struct
import socket

def ethernet_frame(data):
    """
    This function unpacks a frame
    
    @arg - network frame/packet

    @return - destination mac, source mac, type(IP6/IP4 etc.), Unprocessed Data 
    """
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H",data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]

def get_mac(unprocessed):
    """
    Converts unprocessed MAC address to Human readable form

    @args - unprocessed MAC address
    @return - Human readable MAC address
    """
    # print("Unprocessed mac data:",unprocessed)
    low_processed=map('{:02x}'.format,unprocessed)
    final_processed=':'.join(low_processed).upper()
    return final_processed

