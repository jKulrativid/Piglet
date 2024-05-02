<<<<<<< Updated upstream:softwares/dma-proxy/Kernel/Kernel/Kernel0/Makefile
MOD = dma-proxy-0
KPATH :=/lib/modules/$(shell uname -r)/build
PWD :=$(shell pwd)
obj-m = $(MOD).o

=======
.PHONY: all
>>>>>>> Stashed changes:softwares/dma-proxy/Kernel/Makefile
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
