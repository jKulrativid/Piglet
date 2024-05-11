from scapy.all import *

import binascii

def to_p4bm(pkt) -> str:
	packet_hex = binascii.hexlify(raw(pkt)).decode('ascii')

	packet_p4bm = ""

	ff = 0
	for ch in packet_hex:
		packet_p4bm += ch
		if ff:
			packet_p4bm += " "
			ff = 0
		else:
			ff = 1
			
	return packet_p4bm+";\n"


test_inputs = [
	Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=1234)/Raw(load="hey dude"),
	Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=80)/Raw(load="injected")
]

with open("traffic_in.user", "w") as fout:
	for pkt in test_inputs:
		fout.write(to_p4bm(pkt))
#print(test_inputs[0].hexraw())
