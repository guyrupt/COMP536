#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
    Raw
)
from scapy.layers.inet import _IPOption_HDR
from send_query import Query

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


order = []

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("got a packet")
        pkt.show2()
    #    hexdump(pkt)
        if pkt[Raw].load.isdigit():
            order.append(int(pkt[Raw].load))
            if len(order) == 1000:
                print("Order: ", order)
        sys.stdout.flush()
    elif Query in pkt:
        print("got a query")
        pkt.show2()
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
