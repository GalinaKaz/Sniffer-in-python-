#! /usr/bin/python3

import socket
import binascii
import struct
import time

this_time = time.time()


def main():
    print("Sniffer is up, pending for packets")

    with socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as conn:
        ser_num = 1
        while True:
            raw_data, addr = conn.recvfrom(65536)
            packet_size = len(raw_data)
            print('#{}, running time:{:5.2f} , packet size:{}'.format(ser_num, time.time() - this_time, packet_size))
            eth_proto, data_minus_eth_header = ethernet_frame(raw_data)
            if eth_proto == 'IPV4':
                print_packets_v4(data_minus_eth_header)
            elif eth_proto == 'ARP':
                arp_packet(data_minus_eth_header)
            else:
                print("Protocol: {} not parsed".format(eth_proto))
            print("-----------------------------------------------------------------------------------")
            ser_num += 1


# Unpack Ethernet Frame
def ethernet_frame(raw_data):
    eth_header = struct.unpack("!6s6sH", raw_data[0:14])
    dst_mac = binascii.hexlify(eth_header[0], '-').decode()
    src_mac = binascii.hexlify(eth_header[1], '-').decode()
    proto_type = eth_header[2]
    next_proto = hex(proto_type)

    if next_proto == '0x800':
        proto = 'IPV4'
    elif next_proto == '0x806':
        proto = 'ARP'
    elif next_proto == '0x86dd':
        proto = 'IPV6'
    else:
        proto = next_proto
    data_minus_eth_header = raw_data[14:]
    print('ETHERNET: MAC_dst:{}, MAC_src:{}, Next_Protocol:{}'.format(dst_mac, src_mac, proto))

    return proto, data_minus_eth_header


# Unpack APR
def arp_packet(data_input):
    (oper, sender_mac, sender_ip, target_mac, target_ip) = struct.unpack('!6x H 6s 4s 6s 4s', data_input[:28])
    sender_mac = binascii.hexlify(sender_mac, '-').decode()
    target_mac = binascii.hexlify(target_mac, '-').decode()
    if oper == 1:
        oper = 'ARP Request'
    elif oper == 2:
        oper = 'ARP Reply'
    elif oper == 3:
        oper = 'RARP Request'
    elif oper == 4:
        oper = 'RARP Reply'

    print("ARP     : MAC_dst:{}, MAC_src:{}".format(target_mac, sender_mac))
    print("        : Trg_IP:{} , Scr_IP:{}, OPER:{}".format(ipv4(target_ip), ipv4(sender_ip), oper))


# Unpack IP
def print_packets_v4(data_input):
    (version, header_length, ttl, proto, src, target, data_minus_ip_header) = ipv4_packet(data_input)
    print("IP: IP_src:{}, IP_dst:{} , Next proto:{}".format(src, target, proto))

    # ICMP
    if proto == 1:
        icmp_type, code, checksum, data = icmp_packet(data_minus_ip_header)
        print("ICMP: TYPE:{}, CODE:{}".format(icmp_type, code))
    # UDP
    elif proto == 17:
        src_port, dest_port, length, data = udp_seg(data_minus_ip_header)
        print("UDP: scr_PORT:{}, dst_PORT:{}, package_len:{}".format(src_port, dest_port, length))

    # TCP
    elif proto == 6:
        src_port, dest_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_seg(data_minus_ip_header)
        print("TCP: scr_PORT:{}, dst_PORT:{} ,SEQ:{}, ACK:{} , HEADER_len:{}".format(src_port, dest_port, sequence,
                                                                                     acknowledgment, offset))
        print("TCP_FLAGS: URG:{}, ACK:{}, PSH:{}, RST:{}, SYN:{}, FIN:{}".format(flag_urg, flag_ack, flag_psh, flag_rst,
                                                                                 flag_syn, flag_fin))


# Unpack IPv4 Packets Recieved
def ipv4_packet(data):
    version_header_len = data[0]
    ''' the first byte contains 4 bits for VERS and 4 bits for LEN of the IP
    header '''
    version = version_header_len >> 4
    '''shifts to right steps in binary , so only 4 bits first value left'''

    header_len = (version_header_len & 15) * 4
    ''' the binary & by 15 means leave only the  00001111 matches of the 8 bits chain
    only the 4 tail bits left .
    The value  should be 5 usually , 5 *4 = 20 bytes of the IP header'''

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    ''' 
    8x - means ignore the first 8 bytes (VERS,LENS, TOS,Total length, ID , flags , fragment)
    B - is byte for TTL
    B - is byte for Protocol ( the next level TCP/UDP/ICMP ...)
    2x - means ignore for checksum
    4s is 4 bytes with source IP
    4s is 4 bytes with destination IP
    '''
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpacks  ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    if icmp_type == 8:
        icmp_type = 'Echo request'
    elif icmp_type == 0:
        icmp_type = 'Echo reply'
    elif icmp_type == 3:
        icmp_type = 'Destination unreachable'
    elif icmp_type == 4:
        icmp_type = 'Source quench'
    elif icmp_type == 11:
        icmp_type = 'Time exceeded'
    elif icmp_type == 12:
        icmp_type = 'Parameter problem'
    elif icmp_type == 5:
        icmp_type = 'Redirection'
    elif icmp_type == 13:
        icmp_type = 'Timestamp request'
    elif icmp_type == 14:
        icmp_type = 'Timestamp reply'

    return icmp_type, code, checksum, data[4:]


# Unpacks TCP Packet
def tcp_seg(data):
    # struct.unpack('! H H L L H H H H H H', data_minus_ip_header[:24])
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >> 4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return src_port, dest_port, sequence, acknowledgement, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin


# Unpacks UDP Packet
def udp_seg(data):
    src_port, dest_port, size = struct.unpack('!HHH2x', data[:8])
    return src_port, dest_port, size, data[8:]


main()
