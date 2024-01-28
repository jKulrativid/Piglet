#include "../common/pdu.h"
#include "linked_list.h"

using pdu::FiveTuples;

using linked_list::Header;
using linked_list::Node;
using linked_list::LinkedList;



int linked_list_test() {
	LinkedList ll;
	FiveTuples f = {};
	Header h = { .key=1, .five_tuples=f, .first_node_key=1, .fast_ptr_node_key=3 };
	int64_t x = ll.insert_header(h);
	return 0;
}
