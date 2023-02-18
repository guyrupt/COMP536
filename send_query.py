#!/usr/bin/env python3
from scapy.all import *

TYPE_QUERY = 0x812

class Query(Packet):
   fields_desc = [ 
                    BitField("first", 1, 8),
                    IntField("s1_p2_byte_cnt", 0),
                    IntField("s1_p3_byte_cnt", 0)]


bind_layers(Ether, Query, type=TYPE_QUERY)


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

def send_query():

    # if len(sys.argv)<3:
    #     print('pass 2 arguments: <destination> "<message>"')
    #     exit(1)

    addr = "10.0.2.2" # send query result to h2
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt = Ether(src=get_if_hwaddr(iface), dst='08:00:00:00:02:22', type=TYPE_QUERY)
    pkt = pkt / Query()
    
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

def main():
    send_query()

if __name__ == '__main__':
    main()