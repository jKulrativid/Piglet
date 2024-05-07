.PHONY: all
all:
	gcc -o dma-test archived-dma-proxy-test.c

mytest:
	g++ -o my-dma-test my-proxy-test.cpp -lpthread

scaffold:
	g++ -o my-dma-scaffold my-proxy-scaffold.cpp -lpthread

.PHONY: dma-spam-test
dma-spam-test:
	g++ -o dma-spam-test test-dma-spam-rx.cpp