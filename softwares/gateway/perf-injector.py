from multiprocessing import Process
import os
from scapy.all import Ether, IP, UDP
from scapy.all import *


# try to send a packet to the target via an interface dev
def send_packet(dev, packet):
    sendp(packet, iface=dev)
    print(f"Sent packet via {dev}")

# try to send a packet to the target via an interface dev
# 53 - len("Hello World") = 42
# packet2 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.199", dst="192.111.222.123")/UDP(dport=1234)/Raw(load=b"Hello World")
# for i in range(100):
#     send_packet("piglet-loopback", packet1)

# faster sending

# sendpfast(packet1, iface="piglet-loopback", loop=1000, file_cache=True)

# sendpfast with packet1 and 2 simultaneously with different thread



print("Done")


def info(title):
    print(title)
    print('module name:', __name__)
    print('parent process:', os.getppid())
    print('process id:', os.getpid())

if __name__ == '__main__':
    info('main line')

    # pure length 54
    packet1 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(dport=1234)/Raw(load=b""+ b"0"*(1000-54))
    packet2 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(dport=1234)/Raw(load=b""+ b"1"*(550-54))

    p1 = Process(target=sendpfast, args=(packet1, ), kwargs={"iface": "piglet-loopback", "loop": 1, "file_cache": True, "mbps": 30})

    p2 = Process(target=sendpfast, args=(packet2, ), kwargs={"iface": "piglet-loopback", "loop": 1, "file_cache": True, "mbps": 30})

    p1.start()
    p2.start()

    p1.join()
    p2.join()


'''
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 22)));
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 1433)));
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 80)));
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 21)));
'''