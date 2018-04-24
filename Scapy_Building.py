#!/usr/bin/python

from scapy.all import *
import os

incoming_packets = 0
packet_type_count = {'tcp': 0, 'udp': 0, 'icmp': 0, 'arp': 0}
ip_table = {}
interface = 'eno16777736'
host_ip = '10.3.1.110'


def capture_packet(pkt):
    if pkt.haslayer(TCP):
        packet_type_count['tcp'] += 1
    elif pkt.haslayer(UDP):
        packet_type_count['udp'] += 1
    elif pkt.haslayer(ICMP):
        packet_type_count['icmp'] += 1
    elif pkt.haslayer(ARP):
        packet_type_count['arp'] += 1
    count_packets(pkt)
    os.system('clear')
    for k, v in sorted(ip_table.iteritems()):
        print(str(k) + "'s packet count is " + str(v))
    print ("Captured Packet== TCP: %d | UDP: %d | ICMP: %d | ARP: %d" % (packet_type_count['tcp'],
                                                                         packet_type_count['udp'],
                                                                         packet_type_count['icmp'],
                                                                         packet_type_count['arp']))


def count_packets(pkt):  # ip_table function not working as intended
    global incoming_packets
    incoming_packets += 1
    if pkt.haslayer(IP):
        src_ip = str(pkt.getlayer(IP).src)
        dst_ip = str(pkt.getlayer(IP).dst)
        if src_ip is not host_ip:  # THIS DOESN'T WORK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! WHY!!!!!!!!!!!!!!!!!!!
            if src_ip not in ip_table:
                ip_table[src_ip] = 0
            else:
                ip_table[src_ip] += 1
        if dst_ip is not host_ip:
            if dst_ip not in ip_table:
                ip_table[dst_ip] = 0
            else:
                ip_table[dst_ip] += 1


s = sniff(iface=interface, count=500, prn=capture_packet)
