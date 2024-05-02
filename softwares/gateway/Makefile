# there are c files in the current dir that are needed 
# to be compiled into an executable file
# the executable file is gateway

IMPORTED = pcap-utils.c

.PHONY: sniffer
sniffer:
	g++ -o sniffer sniffer-example.cpp $(IMPORTED) -lpcap

.PHONY: injector
injector:
	g++ -o injector injector-example.cpp $(IMPORTED) -lpcap

.PHONY: clean
clean:
	# rm if the file exists
	rm -f sniffer injector

.PHONY: run-sniffer
run-sniffer:
	sudo ./sniffer piglet-loopback ""

.PHONY: run-injector
run-injector:
	sudo ./injector piglet-loopback 100000

all-s: sniffer run-sniffer

all-i: injector run-injector

setup-loopback:
	sudo modprobe dummy && \
	sudo ip link add piglet-loopback type dummy && \
	sudo ip link set piglet-loopback up && \
	sudo ifconfig piglet-loopback hw ether 00:00:00:00:00:01 && \
	ip link show piglet-loopback

# remove-loopback:
# 	sudo ip link delete piglet-loopback
# 	ip link show
