.PHONY: all
all:
	cd Kernel0 && make
	cd Kernel1 && make

.PHONY: insmod
insmod: all
	cd Kernel0 && make insmod
	cd Kernel1 && make insmod
