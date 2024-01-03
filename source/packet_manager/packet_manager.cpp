#include "pdu.h"
#include "parser.h"
#include "flow_table.h"
#include "flow_table.h"
#include "packet_manager.h"

void packet_manager() {
	EthFrame frame;

	parser();
	flow_table();
	data_mover();
}
