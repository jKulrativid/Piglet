from scapy.all import *

import binascii

def to_hex(pkt) -> str:
	return binascii.hexlify(raw(pkt)).decode('ascii')


test_inputs = [
	Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=1234)/Raw(load="hey dude"),
	Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=80)/Raw(load="injected")
]

with open("traffic_in.user", "w") as fout:
	for pkt in test_inputs:
		fout.write(to_hex(pkt) + ";\n")
#print(test_inputs[0].hexraw())
