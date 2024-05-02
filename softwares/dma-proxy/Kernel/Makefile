.PHONY: all
all:
	cd Kernel0 && make
	cd Kernel1 && make

.PHONY: insmod
insmod: all
	cd Kernel0 && make insmod
	cd Kernel1 && make insmod

.PHONY: clean
clean:
	cd Kernel0 && make clean
	cd Kernel1 && make clean

.PHONY: rmmod
rmmod:
	sudo rmmod dma_proxy_0
	sudo rmmod dma_proxy_1
