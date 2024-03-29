#ifndef NETWORK_H_
#define NETWORK_H_

#include "stdint.h"
#include "ap_int.h"

#include "basic_type.h"

namespace pdu
{

/* Transportation Segment */
const int64_t SRC_PORT_SIZE(16);
const int64_t DEST_PORT_SIZE(16);

const int64_t UDP_LEN_SIZE(16);
const int64_t UDP_CHECKSUM_SIZE(16);

const int64_t MSS_SIZE(1460);

class Segment {
public:
	boolean is_tcp;

	ap_uint<SRC_PORT_SIZE> src_port;
	ap_uint<DEST_PORT_SIZE> dest_port;

	ap_uint<UDP_LEN_SIZE> udp_len;
	ap_uint<UDP_CHECKSUM_SIZE> udp_check_sum;

	ap_uint<MSS_SIZE> data;
};

/* Network Packet */
const int64_t V4_VER_SIZE(4);
const int64_t V4_HL_SIZE(4);
const int64_t V4_TOS_SIZE(8);
const int64_t V4_TOTAL_LENGTH_SIZE(16);
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

class Packet {
public :
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
	ap_uint<V4_MAX_OPTIONS_SIZE> v4_options;

	// TODO: handle IP.v6 header extension

	Segment data;
};

/* ETHERNET FRAME */
const int64_t ETH_MAC_ADDR_SIZE(48);
const int64_t ETH_VLAN_TAG_SIZE(32);
const int64_t ETH_PAYLOAD_LEN_SIZE(16);

class EthFrame {
public:
	ap_uint<ETH_MAC_ADDR_SIZE> src_mac, dest_mac;
	ap_uint<ETH_VLAN_TAG_SIZE> vlan_tag;
	ap_uint<ETH_PAYLOAD_LEN_SIZE> payload_len;
	Packet payload;
};

typedef struct {
	ap_uint<V4_PROTOCOL_SIZE> protocol;
	ap_uint<V4_SRC_IP_SIZE> src_ip;
	ap_uint<SRC_PORT_SIZE> src_port;
	ap_uint<V4_DEST_IP_SIZE> dest_ip;
	ap_uint<DEST_PORT_SIZE> dest_port;
} FiveTuples;

};
#endif
