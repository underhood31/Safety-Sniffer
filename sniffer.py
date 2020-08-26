import struct
import socket
import textwrap
from frame import *
from packet import *
from protocol import *
from url_sniffer import *


class sniffer:
    
    def __init__(self):
        self.save=saveUrl()
    def format_multi_line(self,string):
        i=0
        ret=''
        while(len(string)>0):
            if(i==40):
                i=0
                print()
            num=string[0]
            ch=chr(num)
            string=string[1:]
            # print(ch,end=' ')
            if(num>=97 and num<97+26) or (num>=48 and num<58):
                ret+=ch
            else:
                ret+=" "
        return ret
        
    def start_sniffing(self):
        conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
        while True:
            raw_data, addr = conn.recvfrom(65535)
            dest, src, protocol, data=ethernet_frame(raw_data)
            # print("-->Ethernet frame")
            if int(protocol) == 8:
                version, header_len, ttl, IPproto, src_addr, target_addr,data = ipv4_packet(data)
                # print("-->IPv4 Packet:")
                if int(IPproto)==17:
                    src_port, dest_port, size, data=process_udp_packet(data)
                    if dest_port==64:
                        self.save.sniff(self.format_multi_line(data))


