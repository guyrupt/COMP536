/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header record_t {
    bit<16> first_hop;
    bit<16> etherType;
}

header query_t {
    bit<8> first;
    bit<32> s1_p2_byte_cnt;
    bit<32> s1_p3_byte_cnt;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl; //important
    bit<8>    protocol; //important
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr; //important
    ip4Addr_t dstAddr; //important
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/*
metat is defined as below
Think of metadata as local variable whose life span is a single packet
define a metadata is the same as defining a header field.
*/
struct metadata {
    /* empty */
    bit<14> ecmp_select;
}

// There exists predefined standard_metadata with critical functionalities
// For example, changing standard_metadata.egress_spec will change packet egress port.

// header stack, add all the headers you plan to use here.
struct headers {
    ethernet_t   ethernet;
    query_t     query;
    record_t     record;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
	    transition parse_ethernet;
    }

    state parse_ethernet{
	    packet.extract(hdr.ethernet);
	    transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            0x1234: parse_record;
            0x812: parse_query;
        }
	}
	
    state parse_query{
        packet.extract(hdr.query);
        transition accept;
    }

    state parse_record{
        packet.extract(hdr.record);
        transition select(hdr.record.etherType) {
            TYPE_IPV4: parse_ipv4;
        }

    }

    state parse_ipv4 {
	    packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<32>>(8) byte_cnt_reg;
    register<bit<14>>(1) pkt_cnt_reg; // per-packet counter

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_select(bit<14> ecmp_base, bit<14> ecmp_count) {
        // per-flow
        
        // hash(meta.ecmp_select,
        //     HashAlgorithm.crc16,
        //     ecmp_base,
        //     { hdr.ipv4.srcAddr,
        //       hdr.ipv4.dstAddr,
        //       hdr.ipv4.protocol,
        //       hdr.tcp.srcPort,
        //       hdr.tcp.dstPort },
        //     ecmp_count);

        // per-packet 

        bit<14> pkt_cnt;
        pkt_cnt_reg.read(pkt_cnt, 0);
        meta.ecmp_select = pkt_cnt % 2;
        pkt_cnt_reg.write(0, pkt_cnt + 1);

    }

    action set_nhop(macAddr_t nhop_dmac, egressSpec_t egress_port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ethernet.etherType = TYPE_IPV4; // remove the record header
        standard_metadata.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_forward(macAddr_t nhop_dmac, egressSpec_t egress_port) {
        set_nhop(nhop_dmac, egress_port);
    }

    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            drop;
            ipv4_forward;
        }
        size = 1024;
    }


    apply {
        if (hdr.ethernet.etherType == 0x1234 && hdr.record.isValid() && hdr.ipv4.isValid() && hdr.tcp.isValid() && hdr.ipv4.ttl > 0) {
            ecmp_group.apply();
            ecmp_nhop.apply();
            bit<32> byte_cnt;
            byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_spec - 2); // map port 2 to index 0, port 3 to index 1
            byte_cnt = byte_cnt + standard_metadata.packet_length;
            byte_cnt_reg.write((bit<32>)standard_metadata.egress_spec - 2, byte_cnt);
        }
        else if (hdr.ethernet.etherType == TYPE_IPV4 && hdr.ipv4.isValid() && hdr.tcp.isValid() && hdr.ipv4.ttl > 0) {
            ipv4_exact.apply();
        }
        else if (hdr.ethernet.etherType == 0x812 && hdr.query.isValid()) {
            standard_metadata.egress_spec = (bit<9>)2;
            if (hdr.query.first == 1) {
                bit<32> byte_cnt;
                byte_cnt_reg.read(byte_cnt, (bit<32>)0); // port 2
                hdr.query.s1_p2_byte_cnt = byte_cnt;
                byte_cnt_reg.read(byte_cnt, (bit<32>)1); // port 3
                hdr.query.s1_p3_byte_cnt = byte_cnt;
                hdr.query.first = 0;
            }   
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Remove the Record header
        packet.emit(hdr.ethernet);
        packet.emit(hdr.query);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
