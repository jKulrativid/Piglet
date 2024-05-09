#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <sys/param.h>
#include <string.h>
#include <chrono>
#include <atomic>
#include <thread>
#include <string>
#include <iostream>

#include <queue>
#include <mutex>
#include <condition_variable>
#include <utility>

#include "../Common/dma-proxy.h"

#define TX_CHANNEL_COUNT 1
#define RX_CHANNEL_COUNT 2

const char *tx_channel_names[] = { "dma_proxy_tx_0", /* add unique channel names here */ };
const char *rx_channel_names[] = { "dma_proxy_rx_0", "dma_proxy_rx_1",/* add unique channel names here */ };

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
		char s[1000];
		const auto p1 = std::chrono::system_clock::now();
        long long ttt =std::chrono::duration_cast<std::chrono::microseconds>(p1.time_since_epoch()).count();				
		sprintf(s,"[%s] + %d\n",keep_str(ttt,9).c_str(),total_read);
		COUT << s;
		#endif
		
        q.push(t);
        c.notify_one();
    }

	T front(void)
	{
		return q.front();
	}

    // Get the front element.
    // If the queue is empty, wait till a element is avaiable.
    T dequeue(void)
    {

        std::unique_lock<std::mutex> lock(m);
		
		#ifdef DBG_QUEUE
		char s[1000];
		const auto p1 = std::chrono::system_clock::now();
		long long ttt =std::chrono::duration_cast<std::chrono::microseconds>(p1.time_since_epoch()).count();				
		sprintf(s,"[%s] - %d\n",keep_str(ttt,9).c_str(),total_read);
		COUT << s;
        #endif

		while (q.empty())
        {
            // release lock as long as the wait and reaquire it afterwards.
            c.wait(lock);
        }
		
        T val = q.front();
        q.pop();
		
		#ifdef DBG_QUEUE
		const auto _p1 = std::chrono::system_clock::now();
		long long _ttt =std::chrono::duration_cast<std::chrono::microseconds>(_p1.time_since_epoch()).count();				
		sprintf(s,"[%s] ? %d\n",keep_str(_ttt,9).c_str(),total_read);
		COUT << s;
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

SafeQueue<int> sfq;

/* Internal data which should work without tuning */

struct channel {
	struct channel_buffer *buf_ptr;
	int fd;
	pthread_t tid;
	int id;
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

void call_tx(const channel *ch, const int buffer_id, const std::string &test_input) {
	unsigned int test_size = test_input.size();
	if (test_size > BUFFER_SLOT_COUNT) {
		printf("test size greater that buffer size\n");
		return ;
	}

	ch->buf_ptr[buffer_id].length = test_size;
	for (size_t i = 0; i < test_input.size(); i++) {
		ch->buf_ptr[buffer_id].buffer[i] = test_input[i];
	}

	ioctl(ch->fd, XFER, &buffer_id);

	if (ch->buf_ptr[buffer_id].status != channel_buffer::proxy_status::PROXY_NO_ERROR){
		printf("Proxy tx transfer error: error_id=%d\n", ch->buf_ptr[buffer_id].status);
	}
	
	std::cout << "tx finished" << std::endl;
}

void call_rx(const channel *ch, const int buffer_id, const int test_size, std::string &test_output) {
	if (test_size > BUFFER_SLOT_COUNT) {
		printf("test size greater that buffer size\n");
		return ;
	}

	ch->buf_ptr[buffer_id].length = test_size;

	ioctl(ch->fd, START_XFER, &buffer_id);

	int sleep_time_ms = 150;

	while (!stop) {
		ioctl(ch->fd, FINISH_XFER, &buffer_id);

		if (ch->buf_ptr[buffer_id].status != channel_buffer::proxy_status::PROXY_NO_ERROR){
			//printf("Proxy rx transfer error: error_id=%d\n", ch->buf_ptr[buffer_id].status);
			//return "";
			std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time_ms));
			std::cout << "wait " << ch->id << std::endl;
			continue;
		}

		test_output = "";
		for (size_t i = 0; i < test_size; i++) {
			if ((char) ch->buf_ptr[buffer_id].buffer[i] == '\0') break;
			test_output += (char) ch->buf_ptr[buffer_id].buffer[i];
		}

		return;
	}
}

int main(int argc, char *argv[])
{
	int i;
	int max_channel_count = MAX(TX_CHANNEL_COUNT, RX_CHANNEL_COUNT);

	printf("DMA proxy test\n");

	signal(SIGINT, sigint);

	/* Open the file descriptors for each tx channel and map the kernel driver memory into user space */

	for (i = 0; i < TX_CHANNEL_COUNT; i++) {
		tx_channels[i].id = i;
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
		rx_channels[i].id = i;
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

	std::string test_input = "hello capstone";
	std::string test_output0 = "";
	std::string test_output1 = "";
	int test_buffer_id = 0;
	int spam_count = 10;

	std::thread thread1(call_rx, &rx_channels[0], test_buffer_id, 100, std::ref(test_output0));
	std::thread thread2(call_rx, &rx_channels[1], test_buffer_id, 100, std::ref(test_output1));

	sleep(1);

	std::thread thread3(call_tx, &tx_channels[0], test_buffer_id, test_input +  ":" + std::to_string(0));
	std::thread thread4(call_tx, &tx_channels[0], test_buffer_id, test_input +  ":" + std::to_string(1));
	
	thread3.join(); 
	thread4.join();

	thread2.join();
	thread1.join(); 

	std::cout << "output 0 " << test_output0 << " size " << test_output0.size() << std::endl;
	std::cout << "output 1 " << test_output1 << " size " << test_output1.size() << std::endl;

	for (int i =0 ;i < 6; i++) call_tx(&tx_channels[0], test_buffer_id, "short++" + std::to_string(i));

	for (int i = 0; i < 6; i++) {
		call_rx(&rx_channels[i%2], test_buffer_id, 100, std::ref(test_output1));
		std::cout << "output " << i%2 << " ->" << test_output1 << "<- size " << test_output1.size() << std::endl;
	}

	for (i = 0; i < TX_CHANNEL_COUNT; i++) {
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