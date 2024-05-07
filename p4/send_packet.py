from scapy.all import Ether, IP, UDP
from scapy.all import *

# try to send a packet to the target via an interface dev
def send_packet(dev, packet):
    sendp(packet, iface=dev)
    print(f"Sent packet via {dev}")

# try to send a packet to the target via an interface dev
packet1 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.111.222.123")/UDP(dport=1234)/Raw(load=b"Hello World")
# packet2 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.199", dst="192.111.222.123")/UDP(dport=1234)/Raw(load=b"Hello World")
for i in range(1):
    send_packet("piglet-vin", packet1)
# send_packet("piglet-vin", packet2)