#include <core.p4>
#include <xsa.p4>

typedef bit<48>  MacAddr;
typedef bit<32>  IPv4Addr;

const bit<16> QINQ_TYPE = 0x88A8;
const bit<16> VLAN_TYPE = 0x8100;
const bit<16> IPV4_TYPE = 0x0800;

const bit<8>  TCP_PROT  = 0x06;
const bit<8>  UDP_PROT  = 0x11;

// ********************************************************************** //
// *************************** H E A D E R S  *************************** //
// ********************************************************************** //

header eth_mac_t {
    MacAddr dmac; // Destination MAC address
    MacAddr smac; // Source MAC address
    bit<16> type; // Tag Protocol Identifier
}

header vlan_t {
    bit<3>  pcp;  // Priority code point
    bit<1>  cfi;  // Drop eligible indicator
    bit<12> vid;  // VLAN identifier
    bit<16> tpid; // Tag protocol identifier
}

header ipv4_t {
    bit<4>   version;  // Version (4 for IPv4)
    bit<4>   hdr_len;  // Header length in 32b words
    bit<8>   tos;      // Type of Service
    bit<16>  length;   // Packet length in 32b words
    bit<16>  id;       // Identification
    bit<3>   flags;    // Flags
    bit<13>  offset;   // Fragment offset
    bit<8>   ttl;      // Time to live
    bit<8>   protocol; // Next protocol
    bit<16>  hdr_chk;  // Header checksum
    IPv4Addr src;      // Source address
    IPv4Addr dst;      // Destination address
}

header ipv4_opt_t {
    varbit<320> options; // IPv4 options - length = (ipv4.hdr_len - 5) * 32
}

header tcp_t {
    bit<16> src_port;   // Source port
    bit<16> dst_port;   // Destination port
    bit<32> seqNum;     // Sequence number
    bit<32> ackNum;     // Acknowledgment number
    bit<4>  dataOffset; // Data offset
    bit<6>  resv;       // Offset
    bit<6>  flags;      // Flags
    bit<16> window;     // Window
    bit<16> checksum;   // TCP checksum
    bit<16> urgPtr;     // Urgent pointer
}

header tcp_opt_t {
    varbit<320> options; // TCP options - length = (tcp.dataOffset - 5) * 32
}

header udp_t {
    bit<16> src_port;  // Source port
    bit<16> dst_port;  // Destination port
    bit<16> length;    // UDP length
    bit<16> checksum;  // UDP checksum
}

// ********************************************************************** //
// ************************* S T R U C T U R E S  *********************** //
// ********************************************************************** //

// header structure
struct headers {
    eth_mac_t    eth;
    vlan_t       new_vlan;
    vlan_t       vlan;
    ipv4_t       ipv4;
    ipv4_opt_t   ipv4opt;
    tcp_t        tcp;
    tcp_opt_t    tcpopt;
    udp_t        udp;
}

// User metadata structure
struct metadata {
    bit<1> redirect_path;
}

// User-defined errors 
error {
    InvalidIPpacket,
    InvalidTCPpacket
}

// ********************************************************************** //
// *************************** P A R S E R  ***************************** //
// ********************************************************************** //

parser MyParser(packet_in packet, 
                out headers hdr, 
                inout metadata meta, 
                inout standard_metadata_t smeta) {
    
    state start {
        transition parse_eth;
    }
    
    state parse_eth {
        packet.extract(hdr.eth);
        transition select(hdr.eth.type) {
            VLAN_TYPE : parse_vlan;
            IPV4_TYPE : parse_ipv4;
            default   : accept; 
        }
    }
    
    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.tpid) {
            IPV4_TYPE : parse_ipv4;
            default   : accept; 
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4 && hdr.ipv4.hdr_len >= 5,
               error.InvalidIPpacket);
        packet.extract(hdr.ipv4opt, (((bit<32>)hdr.ipv4.hdr_len - 5) * 32));
        transition select(hdr.ipv4.protocol) {
            TCP_PROT  : parse_tcp;
            UDP_PROT  : parse_udp;
            default   : accept; 
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        verify(hdr.tcp.dataOffset >= 5, error.InvalidTCPpacket);
        packet.extract(hdr.tcpopt,(((bit<32>)hdr.tcp.dataOffset - 5) * 32));
        transition accept;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

// ********************************************************************** //
// **************************  P R O C E S S I N G   ******************** //
// ********************************************************************** //

control MyProcessing(inout headers hdr, 
                     inout metadata meta, 
                     inout standard_metadata_t smeta) {
    
    bool is_safe = false;
    
    action pass_to_safe() {
        meta.redirect_path = 1;
    }

    action pass_to_snort() {
        meta.redirect_path = 0;
    }

    action check_source_ipv4() {
        is_safe = is_safe || (hdr.ipv4.isValid() && hdr.ipv4.src == 0x0a9312c8);
    }

    action check_whitelist() {
        check_source_ipv4();
    }

    action check_ip_rules() {

    }

    action check_udp_rules() {

    }

    action check_tcp_rules() {

    }

    apply {
        if (hdr.ipv4.isValid() && hdr.udp.isValid()) {
            check_udp_rules();
        }
        else if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            check_tcp_rules();
        }
        else {
            check_ip_rules();
        }

        if (is_safe) {
            pass_to_safe();
        } else {
            pass_to_snort();
        }
    }
} 

// ********************************************************************** //
// ***************************  D E P A R S E R  ************************ //
// ********************************************************************** //

control MyDeparser(packet_out packet, 
                   in headers hdr,
                   inout metadata meta, 
                   inout standard_metadata_t smeta) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.new_vlan);
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4opt);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcpopt);
        packet.emit(hdr.udp);
    }
}

// ********************************************************************** //
// *******************************  M A I N  **************************** //
// ********************************************************************** //

XilinxPipeline(
    MyParser(), 
    MyProcessing(), 
    MyDeparser()
) main;