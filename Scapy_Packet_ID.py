#!/usr/bin/python

import argparse
import socket
from netaddr import *
from scapy.all import *


parser = argparse.ArgumentParser()
parser.add_argument('count', required=True,
                    help='Provide the number of packets you want to capture')
parser.add_argument('interface', required=True,
                    help='Provide the interface you want to capture from')
args = parser.parse_args()

count_max = args.count
interface = args.interface
local_host = '110.3.1.110'


def ether_check(pkt):  # checks if packet has Ethernet layer
    if pkt.haslayer(Ether):  # pulls out the source and destination MAC addresses
        source_mac = pkt.getlayer(Ether).src
        destination_mac = pkt.getlayer(Ether).dst
        return source_mac, destination_mac
    else:
        return "Non-standard Ethernet frame"


def ip_check(pkt):  # checks if the packet has an IP layer
    if pkt.haslayer(IP):
        source_ip = pkt.getlayer(IP).src
        destination_ip = pkt.getlayer(IP).dst
        return source_ip, destination_ip
    else:
        print("Packet does not have an IP address")


def oui_lookup(mac_addr):  # takes a MAC address and returns the OUI's Organization
    mac = EUI(mac_addr)
    oui = mac.oui
    oui_org = oui.registration().org
    if oui_org:  # checks if the MAC's OUI is registered with IEEE
        return "{0} is owned by {1}".format(mac, oui_org)
    else:
        return "{0} does not have a registered organization with IEEE".format(mac)


def main():
    print oui_lookup(source_mac)


s = sniff(iface=interface, count=count_max, prn=packet_split)