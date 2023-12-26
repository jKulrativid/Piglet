#ifndef NETWORK_H_
#define NETWORK_H_

#include "stdint.h"
#include "ap_int.h"

#include "basic_type.h"

/* Transportation Segment */
const int64_t SRC_PORT_SIZE(16);
const int64_t DEST_PORT_SIZE(16);

const int64_t UDP_LEN_SIZE(16);
const int64_t UDP_CHECKSUM_SIZE(16);

const int64_t TCP_SEQ_NUM_SIZE(32);
const int64_t TCP_ACK_NUM_SIZE(32);
const int64_t TCP_HEADER_LEN_SIZE(4);
const int64_t TCP_RESERVED_SIZE(6);
const int64_t TCP_FLAGS_SIZE(6);
const int64_t TCP_WINDOW_SIZE(16);
const int64_t TCP_CHECKSUM_SIZE(16);
const int64_t TCP_URGENT_POINTER_SIZE(16);
const int64_t TCP_MAX_OPTIONS_SIZE(320);

const int64_t MSS_SIZE(1460);

class Segment {
public:
	boolean is_tcp;

	ap_uint<SRC_PORT_SIZE> src_port;
	ap_uint<DEST_PORT_SIZE> dest_port;

	ap_uint<UDP_LEN_SIZE> udp_len;
	ap_uint<UDP_CHECKSUM_SIZE> udp_check_sum;
	ap_uint<TCP_SEQ_NUM_SIZE> tcp_seq_num;
	ap_uint<TCP_ACK_NUM_SIZE> tcp_ack_num;
	ap_uint<TCP_HEADER_LEN_SIZE> tcp_header_len;
	ap_uint<TCP_RESERVED_SIZE> tcp_reserved;
	ap_uint<TCP_FLAGS_SIZE> tcp_flags;
	ap_uint<TCP_WINDOW_SIZE> tcp_window_size;
	ap_uint<TCP_CHECKSUM_SIZE> tcp_checksum;
	ap_uint<TCP_URGENT_POINTER_SIZE> tcp_urgent_pointer;
	ap_uint<TCP_MAX_OPTIONS_SIZE> tcp_options;

	ap_uint<MSS_SIZE> data;
};

/* Network Packet */

// TODO : implement ICMP PDU (both v4 and v6)
class ICMP {

};

const int64_t V4_VER_SIZE(4);
const int64_t V4_HL_SIZE(4);
const int64_t V4_DSCP_SIZE(6);
const int64_t V4_ECN_SIZE(2);
const int64_t V4_TOTAL_LEN_SIZE(16);
const int64_t V4_IDENTIFICATION_SIZE(16);
const int64_t V4_FLAGS_SIZE(3);
const int64_t V4_FRAGMENT_OFFSET_SIZE(13);
const int64_t V4_TTL_SIZE(8);
const int64_t V4_PROTOCOL_SIZE(8);
const int64_t V4_CHECKSUM_SIZE(16);
const int64_t V4_SRC_IP_SIZE(32);
const int64_t V4_DEST_IP_SIZE(32);
const int64_t V4_MAX_OPTIONS_SIZE(320);

const int64_t V6_VERSION_SIZE(4);
const int64_t V6_TRAFFIC_CLASS_SIZE(6);
const int64_t V6_ECN_SIZE(2);
const int64_t V6_FLOW_LABEL_SIZE(20);
const int64_t V6_PAYLOAD_LEN_SIZE(16);
const int64_t V6_NEXT_HEADER_SIZE(8);
const int64_t V6_HOP_LIMIT_SIZE(8);
const int64_t V6_SRC_ADDR_SIZE(128);
const int64_t V6_DEST_ADDR_SIZE(128);

class Packet {
public :
	boolean is_v6, icmp;

	ap_uint<V4_VER_SIZE> v4_version;
	ap_uint<V4_HL_SIZE> v4_header_len;
	ap_uint<V4_TOS_SIZE> v4_tos;
	ap_uint<V4_TOTAL_LENGTH_SIZE>  v4_total_len;
	ap_uint<V4_IDENTIFICATION_SIZE> v4_identification;
	ap_uint<V4_FLAGS_SIZE> v4_flags;
	ap_uint<V4_FRAGMENT_OFFSET_SIZE> v4_fragment_offset;
	ap_uint<V4_TTL_SIZE> v4_ttl;
	ap_uint<V4_PROTOCOL_SIZE> v4_protocol;
	ap_uint<V4_CHECKSUM_SIZE> v4_checksum;
	ap_uint<V4_SRC_IP_SIZE> v4_src_ip;
	ap_uint<V4_DEST_IP_SIZE> v4_dest_ip;
	ap_uint<V4__MAX_OPTIONS_SIZE> v4_options;

	ap_uint<V6_VERSION_SIZE> v6_version;
	ap_uint<V6_TRAFFIC_CLASS_SIZE> v6_traffic_class;
	ap_uint<V6_ECN_SIZE> v6_ecn;
	ap_uint<V6_FLOW_LABEL_SIZE> v6_flow_label;
	ap_uint<V6_PAYLOAD_LEN_SIZE> v6_payload_len;
	ap_uint<V6_NEXT_HEADER_SIZE> v6_next_header;
	ap_uint<V6_HOP_LIMIT_SIZE> v6_hop_limit;
	ap_uint<V6_SRC_ADDR_SIZE> v6_src_addr;
	ap_uint<V6_DEST_ADDR_SIZE> v6_dest_ip;

	// TODO: handle IP.v6 header extension

	ICMP icmp;
	Segment data;

	Packet() {}
};

/* ETHERNET FRAME */
const int64_t ETH_MAC_ADDR_SIZE(48);
const int64_t ETH_VLAN_TAG_SIZE(32);
const int64_t ETH_PAYLOAD_LEN_SIZE(16);

class EthFrame {
public:
	ap_uint<ETH_MAC_ARRD_SIZE> src_mac, dest_mac;
	ap_uint<ETH_VLAN_TAG_SIZE> vlan_tag;
	ap_uint<ETH_PAYLOAD_LEN_SIZE> payload_len;
	Packet payload;

	EthFrame() {}
};

#endif
