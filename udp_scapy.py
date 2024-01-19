#!/usr/bin/env python3

import sys
import struct
from scapy.all import *

def select_and_send(i, addr, dport, sport):
    if i == 1:
        pkt = IPv6(dst=addr)/UDP(dport=dport, sport=sport)/b"CE_UIT"
    if i == 2:
        print("List of optional Next Header: ")
        print("0. Hop-By-Hop Options.")
        print("43. Routing.")
        print("44. Fragment.")
        print("60. Destination Options.")
        print("1. Routing + Fragment.")
        print("2. Ping.")
        next_header = int(input("Insert your Next Header option: "))
        if next_header == 0:
            pkt = IPv6(dst=addr)/IPv6ExtHdrHopByHop(options=Jumbo(jumboplen=2**30))/UDP(dport=dport, sport=sport)/b"HopByHop"
        if next_header == 43:
            pkt = IPv6(dst=addr)/IPv6ExtHdrRouting(type=0, segleft=0)/UDP(dport=dport, sport=sport)/b"Routing"
        if next_header == 44:
            pkt = IPv6(dst=addr)/IPv6ExtHdrFragment(m=1, id=1)/UDP(dport=dport, sport=sport)/b"Fragment"
        if next_header == 60:
            pkt = IPv6(dst=addr)/IPv6ExtHdrDestOpt()/UDP(dport=dport, sport=sport)/b"Destinantion Options"
        if next_header == 1:
            pkt = IPv6(dst=addr)/IPv6ExtHdrRouting(type=0, segleft=0)/IPv6ExtHdrFragment(m=0, id=1)/UDP(dport=dport, sport=sport)/b"Routing + Fragment"
        if next_header == 2:
            pkt = IPv6(dst=addr)/ICMPv6EchoRequest(data="Ping")
    # s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    # s.bind(('', sport))
    # s.sendto(pkt, (ip.dst, dport))
    send(pkt)

while True:
    print("----- MENU -----\n")
    print("1. Insert IPv6 Address.")
    print("2. Insert PORT using for UDP.")
    print("3. Select and send a pkt.")
    print("0. Exit.\n")
    option = int(input("Select your option: "))
    if option == 0:
        sys.exit()
    if option == 1:
        addr = input("IPv6 Address: ")
    if option == 2:
        dport = int(input("Destination PORT: "))
        sport = int(input("Source PORT: "))
    if option == 3:
        print("----- LIST OF PKTS -----\n")
        print("1. Packet with only payload.")
        print("2. Packet with optional Next Header.")
        i = int(input("Select your type of pkt: "))
        select_and_send(i, addr, dport, sport)
