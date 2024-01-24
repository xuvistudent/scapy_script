#!/usr/bin/env python3

import sys
import struct
from scapy.all import *
from scapy.contrib.rpl import *

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
        print("3. Modified Source Routing Header.")
        print("4. RPLDIO.")
        print("5. RPLDIS.")
        print("6. RPLDAO.")
        print("7. RPLDAOACK.")
        print("8. RPLDCO.")
        print("9. RPLDCOACK.")
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
        if next_header == 3:
            pkt = IPv6(dst=addr)/IPv6ExtHdrRouting(type=3, segleft=2, reserved=0xe0000000, addresses=['fd00::212:4b00:f8e:2300', 'fd00::212:4b00:1204:db4a'])/UDP(dport=dport, sport=sport)/b"CmprI, CmprE" 
        if next_header == 4:
            pkt = IPv6(dst=addr)/ICMPv6RPL()/RPLDIO(RPLInstanceID=255,ver=0,rank=555,mop=3,prf=0x07,dodagid='::dead:beef')/RPLOptRIO()/RPLOptDODAGConfig()/RPLOptTgt()/RPLOptTIO()/RPLOptSolInfo()/RPLOptPIO()/RPLOptTgtDesc()/RPLOptPad1()/RPLOptPadN()
        if next_header == 5:
            pkt = IPv6(dst=addr)/ICMPv6RPL()/RPLDIS()/RPLOptRIO()/RPLOptDODAGConfig()/RPLOptTgt()/RPLOptTIO()/RPLOptSolInfo()/RPLOptPIO()/RPLOptTgtDesc()/RPLOptPad1()/RPLOptPadN()
        if next_header == 6:
            pkt = IPv6(dst=addr)/ICMPv6RPL()/RPLDAO(RPLInstanceID=113,K=1,D=1,daoseq=3,dodagid='::dead:beef')/RPLOptRIO()/RPLOptDODAGConfig()/RPLOptTgt()/RPLOptTIO()/RPLOptSolInfo()/RPLOptPIO()/RPLOptTgtDesc()/RPLOptPad1()/RPLOptPadN()
        if next_header == 7:
            pkt = IPv6(dst=addr)/ICMPv6RPL()/RPLDAOACK(RPLInstanceID=115,D=1,daoseq=6,status=0,dodagid='::dead:beef')/RPLOptRIO()/RPLOptDODAGConfig()/RPLOptTgt()/RPLOptTIO()/RPLOptSolInfo()/RPLOptPIO()/RPLOptTgtDesc()/RPLOptPad1()/RPLOptPadN()
        if next_header == 8:
            pkt = IPv6(dst=addr)/ICMPv6RPL()/RPLDCO(RPLInstanceID=116,K=1,D=1,dcoseq=9,dodagid='::dead:beef')/RPLOptRIO()/RPLOptDODAGConfig()/RPLOptTgt()/RPLOptTIO()/RPLOptSolInfo()/RPLOptPIO()/RPLOptTgtDesc()/RPLOptPad1()/RPLOptPadN()
        if next_header == 9:
            pkt = IPv6(dst=addr)/ICMPv6RPL()/RPLDCOACK(D=1,dcoseq=12,dodagid='::dead:beef')/RPLOptRIO()/RPLOptDODAGConfig()/RPLOptTgt()/RPLOptTIO()/RPLOptSolInfo()/RPLOptPIO()/RPLOptTgtDesc()/RPLOptPad1()/RPLOptPadN()
 
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
