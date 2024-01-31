#include <iostream>

#include "linked_list_test.h"
#include "packet_manager_test.h"
#include "reassembler_test.h"

int main() {
	int ret;

	ret = linked_list_test();
	if (ret != 0) {
		return ret;
	}

	ret = packet_manager_test();
	if (ret != 0) {
		return ret;
	}

	ret = reassembler_test();
	if (ret != 0) {
		return ret;
	}

	std::cout << "Test Finished Successfully" << std::endl;

	return ret;
}
