open_project piglet_packet_manager_tcl_test

add_files ../source/common/basic_type.h
add_files ../source/packet_manager/buffer.cpp
add_files ../source/packet_manager/buffer.h
add_files ../source/packet_manager/flow_table.cpp
add_files ../source/packet_manager/flow_table.h
add_files ../source/packet_manager/packet_manager.cpp
add_files ../source/packet_manager/packet_manager.h
add_files ../source/packet_manager/parser.cpp
add_files ../source/packet_manager/parser.h
add_files ../source/packet_manager/pdu.cpp
add_files ../source/packet_manager/pdu.h

add_files -tb ../source/packet_manager/packet_manager_test.cpp
open_solution "piglet-packet-manager" -flow_target vivado
set_part {xc7z010iclg225-1L}
create_clock -period 10 -name default
csim_design
csynth_design
cosim_design
export_design -format ip_catalog
