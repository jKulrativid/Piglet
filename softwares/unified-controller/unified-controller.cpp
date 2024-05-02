/**
 * Copyright (C) 2021 Xilinx, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/* DMA Proxy Test Application
 *
 * This application is intended to be used with the DMA Proxy device driver. It provides
 * an example application showing how to use the device driver to do user space DMA
 * operations.
 *
 * The driver allocates coherent memory which is non-cached in a s/w coherent system
 * or cached in a h/w coherent system.
 *
 * Transmit and receive buffers in that memory are mapped to user space such that the
 * application can send and receive data using DMA channels (transmit and receive).
 *
 * It has been tested with AXI DMA and AXI MCDMA systems with transmit looped back to
 * receive. Note that the receive channel of the AXI DMA throttles the transmit with
 * a loopback while this is not the case with AXI MCDMA.
 *
 * Build information: The pthread library is required for linking. Compiler optimization
 * makes a very big difference in performance with -O3 being good performance and
 * -O0 being very low performance.
 *
 * The user should tune the number of channels and channel names to match the device
 * tree.
 *
 * More complete documentation is contained in the device driver (dma-proxy.c).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <thread>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <sys/param.h>

#include <queue>
#include <mutex>
#include <condition_variable>
#include <utility>
#include <chrono>
#include <pcap.h>

#include "../dma-proxy/Common/dma-proxy.h"
#include "../gateway/pcap-utils.h"

#define ETH_IN_DEV "eth0"

// A threadsafe-queue.
template <class T>
class SafeQueue
{
public:
    SafeQueue() : q(), m(), c() {}

    ~SafeQueue() {}

	
    // Add an element to the queue.
    void enqueue(T t)
    {

        std::lock_guard<std::mutex> lock(m);
		#ifdef DBG_QUEUE
		//char s[1000];
		//const auto p1 = std::chrono::system_clock::now();
        //long long ttt =std::chrono::duration_cast<std::chrono::microseconds>(p1.time_since_epoch()).count();				
		//sprintf(s,"[%s] + %d\n",keep_str(ttt,9).c_str(),total_read);
		//COUT << s;
		#endif
		
        q.push(t);
        c.notify_one();
    }

    // Get the front element.
    // If the queue is empty, wait till a element is avaiable.
    T dequeue(void)
    {

        std::unique_lock<std::mutex> lock(m);
		
		#ifdef DBG_QUEUE
		//char s[1000];
		//const auto p1 = std::chrono::system_clock::now();
		//long long ttt =std::chrono::duration_cast<std::chrono::microseconds>(p1.time_since_epoch()).count();				
		//sprintf(s,"[%s] - %d\n",keep_str(ttt,9).c_str(),total_read);
		//COUT << s;
        #endif

		while (q.empty())
        {
            // release lock as long as the wait and reaquire it afterwards.
            c.wait(lock);
        }
		
        T val = q.front();
        q.pop();
		
		#ifdef DBG_QUEUE
		//const auto _p1 = std::chrono::system_clock::now();
		//long long _ttt =std::chrono::duration_cast<std::chrono::microseconds>(_p1.time_since_epoch()).count();				
		//sprintf(s,"[%s] ? %d\n",keep_str(_ttt,9).c_str(),total_read);
		//COUT << s;
		#endif

        return val;
    }
	template< class Rep, class Period>
	bool wait_empty(const std::chrono::duration<Rep, Period>& rel_time) {
        std::unique_lock<std::mutex> lock(m);
        if (q.empty())
        {
            // release lock as long as the wait and reaquire it afterwards.
            c.wait_for(lock, rel_time);
        }
		return q.empty();
	}
    int size() {
	std::unique_lock<std::mutex> lock(m);
        return q.size();
    }
    bool empty() {
		std::unique_lock<std::mutex> lock(m);
		return q.empty();
    }

private:
    std::queue<T> q;
    mutable std::mutex m;
    std::condition_variable c;
};

/* The user must tune the application number of channels to match the proxy driver device tree
 * and the names of each channel must match the dma-names in the device tree for the proxy
 * driver node. The number of channels can be less than the number of names as the other
 * channels will just not be used in testing.
 */
#define TX_CHANNEL_COUNT 1
#define RX_CHANNEL_COUNT 1

const char *tx_channel_names[] = { "dma_proxy_tx_0",  /* add unique channel names here */ };
const char *rx_channel_names[] = { "dma_proxy_rx_0", "dma_proxy_rx_1" /* add unique channel names here */ };

/* Internal data which should work without tuning */

struct channel {
	struct channel_buffer *buf_ptr;
	int fd;
	pthread_t tid;
};

static int verify;
static int test_size;
static volatile int stop = 0;
int num_transfers;

struct channel tx_channels[TX_CHANNEL_COUNT], rx_channels[RX_CHANNEL_COUNT];

/*******************************************************************************************************************/
/* Handle a control C or kill, maybe the actual signal number coming in has to be more filtered?
 * The stop should cause a graceful shutdown of all the transfers so that the application can
 * be started again afterwards.
 */
void sigint(int a)
{
	stop = 1;
}

/*******************************************************************************************************************/
/* Get the clock time in usecs to allow performance testing
 */
static uint64_t get_posix_clock_time_usec ()
{
    struct timespec ts;

    if (clock_gettime (CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t) (ts.tv_sec * 1000000 + ts.tv_nsec / 1000);
    else
        return 0;
}

/*******************************************************************************************************************/
/*
 * The following function is the transmit thread to allow the transmit and the receive channels to be
 * operating simultaneously. Some of the ioctl calls are blocking so that multiple threads are required.
 */

void tx_thread(struct channel *channel_ptr)
// channel *channel_ptr is not used
{
	printf("start tx thread\n");
	int i, counter = 0, buffer_id, in_progress_count = 0;
	int stop_in_progress = 0;

	SafeQueue<int> emptyQueue;
	SafeQueue<int> workingQueue;
	// initiate pcap
	char *dev = (char*)ETH_IN_DEV;
	char filter_exp[] = "port 22";
	pcap_t *handle;
	struct bpf_program fp;
	handle = initiate_sniff_pcap(&fp, dev, filter_exp);
	if (handle == NULL) {
		printf("Error status\n");
		exit(EXIT_FAILURE);
	}

	// Start all buffers being sent

	for (buffer_id = 0; buffer_id < TX_BUFFER_COUNT; buffer_id += BUFFER_INCREMENT) {
		emptyQueue.enqueue(buffer_id);
	}
 
	using namespace std::chrono_literals;
	std::thread finished_watcher([&]() {
		while(!stop) {
			if (!workingQueue.wait_empty(1000us)) {
				int buffer_id = workingQueue.dequeue();
				ioctl(channel_ptr->fd, FINISH_XFER, &buffer_id);
				emptyQueue.enqueue(buffer_id);
			}
		}
	});

	while (!stop) {
		struct pcap_pkthdr *header;
        const u_char *packet;
        pcap_next_ex(handle, &header, &packet);

		auto caplen = header->caplen;

		int buffer_id = emptyQueue.dequeue();
		memcpy(channel_ptr->buf_ptr[buffer_id].buffer, packet, caplen);
		channel_ptr->buf_ptr[buffer_id].length = caplen;

		workingQueue.enqueue(buffer_id);

		ioctl(channel_ptr->fd, START_XFER, &buffer_id);
	}

	finished_watcher.join();
	printf("tx thread finished\n");
}

void rx_thread(struct channel *channel_ptr)
{
	printf("start rx thread\n");
	int in_progress_count = 0, buffer_id = 0;
	int rx_counter = 0;

	SafeQueue<int> emptyQueue;
	SafeQueue<int> workingQueue;

	// Start all buffers being received

	for (buffer_id = 0; buffer_id < RX_BUFFER_COUNT; buffer_id += BUFFER_INCREMENT) {

		/* Don't worry about initializing the receive buffers as the pattern used in the
		 * transmit buffers is unique across every transfer so it should catch errors.
		 */
		channel_ptr->buf_ptr[buffer_id].length = BUFFER_SIZE / sizeof(unsigned int);

		// ioctl(channel_ptr->fd, START_XFER, &buffer_id);

		/* Handle the case of a specified number of transfers that is less than the number
		 * of buffers
		 */
		// if (++in_progress_count >= num_transfers)
		// 	break;
		emptyQueue.enqueue(buffer_id);
	}

	using namespace std::chrono_literals;
	std::thread finished_watcher([&]() {
		while(!stop) {
			if (!workingQueue.wait_empty(1000us)) {
				// retrieve packet
				u_char packet[BUFFER_SIZE / sizeof(unsigned int)];

				int buffer_id = workingQueue.dequeue();
				ioctl(channel_ptr->fd, FINISH_XFER, &buffer_id);

				if (channel_ptr->buf_ptr[buffer_id].status != channel_buffer::proxy_status::PROXY_NO_ERROR) {
					printf("Proxy number %llu error: %d\n", channel_ptr->tid, channel_ptr->buf_ptr[buffer_id].status);
					printf("Proxy rx transfer error,# buffer %d, # transfers %d, # completed %d, # in progress %d\n",
								buffer_id, num_transfers, rx_counter, in_progress_count);
				}

				memcpy(&packet, channel_ptr->buf_ptr[buffer_id].buffer, channel_ptr->buf_ptr[buffer_id].length);
				emptyQueue.enqueue(buffer_id);

				// get packet size
				parsed_packet pp = parse_packet(packet);
				int total_size = SIZE_ETHERNET + pp.size_ip + pp.size_tcp + pp.size_payload;
			}
		}
	});

	while(!stop) {
		int buffer_id = emptyQueue.dequeue();
		ioctl(channel_ptr->fd, START_XFER, &buffer_id);
		workingQueue.enqueue(buffer_id);
	}


	printf("rx thread finished");
}

/*******************************************************************************************************************/
/*
 * Setup the transmit and receive threads so that the transmit thread is low priority to help prevent it from
 * overrunning the receive since most testing is done without any backpressure to the transmit channel.
 */
void setup_threads()
{
	pthread_attr_t tattr_tx;
	int newprio = 20, i;
	struct sched_param param;

	/* The transmit thread should be lower priority than the receive
	 * Get the default attributes and scheduling param
	 */
	pthread_attr_init (&tattr_tx);
	pthread_attr_getschedparam (&tattr_tx, &param);

	/* Set the transmit priority to the lowest
	 */
	param.sched_priority = newprio;
	pthread_attr_setschedparam (&tattr_tx, &param);

	// there is only one tx channel
	pthread_create(&tx_channels[i].tid, &tattr_tx, (void* (*)(void*))tx_thread, (void *)&tx_channels[i]);

	for (i = 0; i < RX_CHANNEL_COUNT; i++)
		pthread_create(&rx_channels[i].tid, NULL, (void* (*)(void*))rx_thread, (void *)&rx_channels[i]);

}

/*******************************************************************************************************************/
/*
 * The main program starts the transmit thread and then does the receive processing to do a number of DMA transfers.
 */
int main(int argc, char *argv[])
{
	int i;
	uint64_t start_time, end_time, time_diff;
	int mb_sec;
	int buffer_id = 0;
	int max_channel_count = MAX(TX_CHANNEL_COUNT, RX_CHANNEL_COUNT);

	printf("DMA proxy test\n");

	signal(SIGINT, sigint);

	/* Open the file descriptors for each tx channel and map the kernel driver memory into user space */

	for (i = 0; i < TX_CHANNEL_COUNT; i++) {
		char channel_name[64] = "/dev/";
		strcat(channel_name, tx_channel_names[i]);
		tx_channels[i].fd = open(channel_name, O_RDWR);
		if (tx_channels[i].fd < 1) {
			printf("Unable to open DMA proxy device file: %s\r", channel_name);
			exit(EXIT_FAILURE);
		}
		tx_channels[i].buf_ptr = (struct channel_buffer *)mmap(NULL, sizeof(struct channel_buffer) * TX_BUFFER_COUNT,
										PROT_READ | PROT_WRITE, MAP_SHARED, tx_channels[i].fd, 0);
		if (tx_channels[i].buf_ptr == MAP_FAILED) {
			printf("Failed to mmap tx channel\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Open the file descriptors for each rx channel and map the kernel driver memory into user space */

	for (i = 0; i < RX_CHANNEL_COUNT; i++) {
		char channel_name[64] = "/dev/";
		strcat(channel_name, rx_channel_names[i]);
		rx_channels[i].fd = open(channel_name, O_RDWR);
		if (rx_channels[i].fd < 1) {
			printf("Unable to open DMA proxy device file: %s\r", channel_name);
			exit(EXIT_FAILURE);
		}
		rx_channels[i].buf_ptr = (struct channel_buffer *)mmap(NULL, sizeof(struct channel_buffer) * RX_BUFFER_COUNT,
										PROT_READ | PROT_WRITE, MAP_SHARED, rx_channels[i].fd, 0);
		if (rx_channels[i].buf_ptr == MAP_FAILED) {
			printf("Failed to mmap rx channel\n");
			exit(EXIT_FAILURE);
		}
	}

	setup_threads();
	/* Clean up all the channels before leaving */

	for (i = 0; i < TX_CHANNEL_COUNT; i++) {
		pthread_join(tx_channels[i].tid, NULL);
		munmap(tx_channels[i].buf_ptr, sizeof(struct channel_buffer));
		close(tx_channels[i].fd);
	}
	for (i = 0; i < RX_CHANNEL_COUNT; i++) {
		munmap(rx_channels[i].buf_ptr, sizeof(struct channel_buffer));
		close(rx_channels[i].fd);
	}

	printf("DMA proxy test complete\n");

	return 0;
}
