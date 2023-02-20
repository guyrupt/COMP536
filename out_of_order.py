#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import Packet, ShortField, BitField, IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp, bind_layers

class Record(Packet):
    name = "record"
    fields_desc = [
                    ShortField("first_hop", 1),
                    ShortField("protocol", 0)
    ]
                   

bind_layers(Ether, Record, type=0x1234)
bind_layers(Record, IP, protocol=0x0800)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    # if len(sys.argv)<3:
    #     print('pass 2 arguments: <destination> "<message>"')
    #     exit(1)

    addr = "10.0.2.2"
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))

    packets = []
    for i in range(1000):
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=0x1234)
        pkt = pkt / Record(first_hop=1)
        pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=10000) / str(i)
        packets.append(pkt)

    sendp(packets, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
