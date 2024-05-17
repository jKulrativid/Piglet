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
	sudo ./sniffer enx2887ba3e44aa ""

.PHONY: run-injector
run-injector:
	sudo ./injector piglet-loopback 100000

all-s: sniffer run-sniffer

all-i: injector run-injector

setup-loopback:
	sudo modprobe dummy && \
	sudo ip link add piglet-vin type dummy && \
	sudo ip link set piglet-vin up && \
	sudo ifconfig piglet-vin hw ether 00:00:00:00:00:01 && \
	sudo ip link add piglet-snort type dummy && \
	sudo ip link set piglet-snort up && \
	sudo ifconfig piglet-snort hw ether 00:00:00:00:00:02 && \
	sudo ip link add piglet-vout type dummy && \
	sudo ip link set piglet-vout up && \
	sudo ifconfig piglet-vout hw ether 00:00:00:00:00:03 && \
	ip link show

# remove-loopback:
# 	sudo ip link delete piglet-loopback
# 	ip link show

.PHONY: perf-sniffer
perf-sniffer:
	cat perf-sniffer.cpp | grep argc
	g++ -O2 -o perf-sniffer perf-sniffer.cpp $(IMPORTED) -lpcap

run-perf-sniffer:
	sudo ./perf-sniffer enx2887ba3e44aa "" 101 1000 0 0

all-perf-s: perf-sniffer run-perf-sniffer

.PHONY: all-perf-i
all-perf-i: 
	sudo python3 perf-injector.py
