from multiprocessing import Process
import os
from scapy.all import Ether, IP, UDP
from scapy.all import *
import sys


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






def info(title):
    print(title)
    print('module name:', __name__)
    print('parent process:', os.getppid())
    print('process id:', os.getpid())

def pad_message(m, l):
    TCP_LENGTH = 54
    padding_message = "-PADDING-"
    lm = len(m)
<<<<<<< HEAD
    try:
        assert TCP_LENGTH + lm <= l
    except AssertionError:
        print(f"Warning: Message length {lm} is too long for packet size {l}")
=======
    assert TCP_LENGTH + lm <= l
>>>>>>> a97e83d (save progress)
    padded_len = l - (TCP_LENGTH + lm)
    padding_message *= int(1 + padded_len/len(padding_message))
    padded_message = m + padding_message
    return padded_message[:(l-TCP_LENGTH)]

<<<<<<< HEAD
# print(len(pad_message("helloworld", 93)), pad_message("helloworld", 93))
=======
print(len(pad_message("helloworld", 93)), pad_message("helloworld", 93))
>>>>>>> a97e83d (save progress)
assert len(pad_message("helloworld", 93)) == 93-54


if __name__ == '__main__':
    info('main line')
    # get cli arguments: <pkt1-size> <pkt1-repeats> <pkt2-size> <pkt2-repeats>
    if len(sys.argv) != 7:
        print("Usage: python3 perf-injector.py <pkt1-size> <pkt1-repeats> <pps1> <pkt2-size> <pkt2-repeats> <pps2>")
        sys.exit(1)
    pkt1_size = int(sys.argv[1])
    pkt1_repeats = int(sys.argv[2])
    pps1 = int(sys.argv[3])
    pkt2_size = int(sys.argv[4])
    pkt2_repeats = int(sys.argv[5])
    pps2 = int(sys.argv[6])



    # test_inputs = [
    #     Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=1234)/Raw(load="hey dude"),
    #     Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=80)/Raw(load="injected haha")
    # ]
    # pure length 54
    pkt1_len = pkt1_size
    message1 = pad_message("Harmless Packet", pkt1_len)
    pkt2_len = pkt2_size
    message2 = pad_message("Suspicious Packet", pkt2_len)


    packet1 = Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=1234)/Raw(load=message1)
    packet2 = Ether(src="08:00:27:00:00:02",dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(sport=5000,dport=80)/Raw(load=message2)
    # packet1 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(dport=1234)/Raw(load=b""+ b"0"*(102-54))
    # packet2 = Ether(dst="08:00:27:00:00:01")/IP(src="10.147.18.200", dst="192.168.1.56")/TCP(dport=1234)/Raw(load=b""+ b"1"*(97-54))
<<<<<<< HEAD

    p1 = Process(target=sendpfast, args=(packet1, ), kwargs={"iface": "en13", "loop": pkt1_repeats, "file_cache": True, "mbps": 1000, "pps": pps1})

    p2 = Process(target=sendpfast, args=(packet2, ), kwargs={"iface": "en13", "loop": pkt2_repeats, "file_cache": True, "mbps": 1000, "pps": pps2})

    if pkt1_repeats > 0:
        p1.start()
    if pkt2_repeats > 0:
        p2.start()

    if pkt1_repeats > 0:
        p1.join()
    if pkt2_repeats > 0:
        p2.join()

=======

    p1 = Process(target=sendpfast, args=(packet1, ), kwargs={"iface": "enx2887ba3e44aa", "loop": 1000, "file_cache": True, "mbps": 1000, "pps": 170_000})

    p2 = Process(target=sendpfast, args=(packet2, ), kwargs={"iface": "enx2887ba3e44aa", "loop": 1, "file_cache": True, "mbps": 1000})

    p1.start()
    # p2.start()

    p1.join()
    # p2.join()
>>>>>>> a97e83d (save progress)


'''
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 22)));
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 1433)));
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 80)));
is_safe = is_safe && !(((hdr.ipv4.src & 0x0) == 0x00000000) && ((hdr.ipv4.dst & 0xffffff00) == 0xc0a80138) && ((hdr.tcp.dst_port == 21)));
'''
