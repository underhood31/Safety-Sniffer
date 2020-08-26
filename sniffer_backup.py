import struct
import socket
import textwrap
from frame import *
from packet import *
from protocol import *
import url_sniffer
def format_multi_line(prefix, string, size=80):
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
    
def start_sniffing():
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest, src, protocol, data=ethernet_frame(raw_data)
        # print("-->Ethernet frame")
        # print('Destination: {}, Source: {}, Protocol: {}'.format(dest,src,protocol))
        if int(protocol) == 8:
            version, header_len, ttl, IPproto, src_addr, target_addr,data = ipv4_packet(data)
            # print("-->IPv4 Packet:")
            # print('Version: {}, Header Length: {}, TTL: {}, IP Protocol: {}, Source Addr: {}, Dest Addr: {}'.format(version, header_len, ttl, IPproto, src_addr, target_addr))

            if int(IPproto)==1:
                icmp_type, code, checksum, data=process_icmp_packet(data)
                # print("-->ICMP packet Details:")
                # print('ICMP Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                # print("Data-->")
                # print(format_multi_line('',data))
            elif int(IPproto)==6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data=process_tcp_packet(data)
                # print("-->TCP packet Details:")
                # print('Src Port: {}, Dest Port: {}, Sequence: {}, Acknowledgement: {}, flag_urg: {}'.format(src_port, dest_port, sequence, acknowledgement, flag_urg))
                # print(' flag_ack: {}, flag_psh: {}, flag_rst: {}, flag_syn: {}, flag_fin: {}'.format(flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                # print("Data-->")
                # print(format_multi_line('',data))
                # print(src_port,dest_port)
            elif int(IPproto)==17:
                src_port, dest_port, size, data=process_udp_packet(data)
                # print("-->UDP packet Details:")
                # print('Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))
                # print("Data-->")
                # if dest_port==53:
                # print(src_port,dest_port)
                if dest_port==64:
                    print(format_multi_line('',data))



if __name__ == "__main__":
    start_sniffing()