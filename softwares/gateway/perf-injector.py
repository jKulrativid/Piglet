from scapy.all import Ether, IP, UDP
from scapy.all import *

# for multiprocessing
from multiprocessing import Process

# try to send a packet to the target via an interface dev
def send_packet(dev, packet):
    sendp(packet, iface=dev)
    print(f"Sent packet via {dev}")

# try to send a packet to the target via an interface dev
packet1 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.111.222.123")/UDP(dport=1234)/Raw(load=b"Hello World"+ b"0"*1000)
packet2 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.111.222.123")/UDP(dport=1234)/Raw(load=b"Hello World"+ b"1"*200)
# 53 - len("Hello World") = 42
# packet2 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.199", dst="192.111.222.123")/UDP(dport=1234)/Raw(load=b"Hello World")
# for i in range(100):
#     send_packet("piglet-loopback", packet1)
# send_packet("piglet-vin", packet2)

# faster sending

# sendpfast(packet1, iface="piglet-loopback", loop=1000, file_cache=True)

# sendpfast with packet1 and 2 simultaneously with different thread

p1 = Process(target=sendpfast, args=(packet1, ), kwargs={"iface": "piglet-loopback", "loop": 200, "file_cache": True, "mbps": 50})

p2 = Process(target=sendpfast, args=(packet2, ), kwargs={"iface": "piglet-loopback", "loop": 400, "file_cache": True, "mbps": 50})

p1.start()
p2.start()

p1.join()
p2.join()

print("Done")