#ifndef LINKED_LIST_H_
#define LINKED_LIST_H_

#include <ap_int.h>

#include "../common/pdu.h"

#define LL_HEADER_MEM_SIZE 1024
#define LL_NODE_MEM_SIZE 2048

namespace linked_list
{

const int64_t HEADER_KEY_SIZE(32);

const int64_t NODE_KEY_SIZE(32);

typedef struct {
	ap_uint<HEADER_KEY_SIZE> key;
	pdu::FiveTuples five_tuples;
	ap_uint<NODE_KEY_SIZE> first_node_key;
	ap_uint<NODE_KEY_SIZE> fast_ptr_node_key;
} Header;

typedef struct {
	ap_uint<NODE_KEY_SIZE> key;
	ap_uint<1> mf;
	ap_uint<pdu::V4_TOTAL_LEN_SIZE> offset;
	ap_uint<pdu::V4_TOTAL_LEN_SIZE> end;
	ap_uint<NODE_KEY_SIZE> next;
} Node;

class LinkedList {
private:
	Header header_mem[LL_HEADER_MEM_SIZE];
	Node node_mem[LL_NODE_MEM_SIZE];
	int64_t hash_node(Node& node);
	int64_t hash_header(Header& header);
public:
	int64_t find_node(int64_t key, Node& node);
	int64_t insert_node(Node& node);
	int64_t update_node(Node& node);
	int64_t delete_node(Node& node);

	int64_t find_header_by_five_tuples(pdu::FiveTuples& five_tuples, Header& header);
	int64_t insert_header(Header& header);
	int64_t update_header(Header& header);
	int64_t delete_header(Header& header);

	LinkedList();
};

};

#endif
