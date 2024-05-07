# Description: Makefile for unified-controller

IMPORTED = ../gateway/pcap-utils.c 

CFLAGS = 
LDFLAGS = -lpcap -pthread

.PHONY: unified-controller
unified-controller:
	g++ -o unified-controller unified-controller.cpp $(IMPORTED) $(CFLAGS) $(LDFLAGS)

.PHONY: clean
clean:
	rm unified-controller

.PHONY: run
run:
	sudo ./unified-controller ens34

all: unified-controller run


