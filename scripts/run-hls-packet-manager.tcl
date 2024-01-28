open_project ../generated/piglet_packet_manager_tcl_test

# common package
add_files ../source/common/basic_type.h
add_files ../source/common/pdu.cpp
add_files ../source/common/pdu.h

# packet manager package
add_files ../source/packet_manager/linked_list.h
add_files ../source/packet_manager/linked_list.cpp

# packet manager testbench
add_files -tb ../source/packet_manager/linked_list_test.h
add_files -tb ../source/packet_manager/linked_list_test.cpp

# top module

add_files -tb ../source/packet_manager/top_test.cpp

open_solution "piglet-packet-manager" -flow_target vivado
set_part {xcvu11p-flga2577-1-e}
create_clock -period 10 -name default
csim_design
csynth_design
cosim_design
export_design -format ip_catalog
