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

#include <pcap.h>

#include "../dma-proxy/Common/dma-proxy.h"
#include "../gateway/pcap-utils.h"

/* The user must tune the application number of channels to match the proxy driver device tree
 * and the names of each channel must match the dma-names in the device tree for the proxy
 * driver node. The number of channels can be less than the number of names as the other
 * channels will just not be used in testing.
 */
#define TX_CHANNEL_COUNT 1
#define RX_CHANNEL_COUNT 2

#define MAX_PKT_SIZE 64 // KB

const char *tx_channel_names[] = { "dma_proxy_tx_0", /* add unique channel names here */ };
const char *rx_channel_names[] = { "dma_proxy_rx_0", "dma_proxy_rx_1",/* add unique channel names here */ };

/* Internal data which should work without tuning */

struct channel {
	struct channel_buffer *buf_ptr;
	int fd;
	pthread_t tid;
};

static int verify;
static int test_size = MAX_PKT_SIZE * 1024;
static volatile int stop = 0;
int num_transfers;

struct channel tx_channels[TX_CHANNEL_COUNT], rx_channels[RX_CHANNEL_COUNT];

pcap_t *sniffer_handle;				
struct bpf_program s_fp;

pcap_t *inject_snort_handle;

pcap_t *inject_egress_handle;			

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
{
	int i, counter = 0, buffer_id=0, in_progress_count = 0;
	int stop_in_progress = 0;

	// Start all buffers being sent

	while(!stop){

		if (stop & !stop_in_progress) {
			stop_in_progress = 1;
			num_transfers = counter + RX_BUFFER_COUNT;
		}
	

		// wait for packet to come in
		
		struct pcap_pkthdr *header;
        const u_char *packet;
		while(!stop){
        	int status = pcap_next_ex(sniffer_handle, &header, &packet);
			if (status == 1){
				//printf("pktlen:%d, pktcaplen:%d\n", header->len, header->caplen);
				channel_ptr->buf_ptr[buffer_id].length = test_size;
				break;
			}
			if (status == 0){
				// printf("timeout\n");
				continue;
			}
			if (status == -1){
				//fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(sniffer_handle));
				continue;
			}
		}
		
		parsed_packet parsed_packet = parse_packet(packet);
		int l4_size;
		if (parsed_packet.tcp != nullptr) {
			l4_size = parsed_packet.size_tcp;
		} else {
			l4_size = parsed_packet.size_udp;
		}
		int packet_size = SIZE_ETHERNET + parsed_packet.size_ip + l4_size + parsed_packet.size_payload;
		int status = pcap_inject(inject_egress_handle, packet, packet_size);
		if (status == -1){
			fprintf(stderr, "Error sending packet to egress: %s\n", pcap_geterr(inject_egress_handle));
		}

		if (channel_ptr->buf_ptr[buffer_id].status != channel_buffer::proxy_status::PROXY_NO_ERROR){
			printf("Proxy tx transfer error: error_id=%d\n", channel_ptr->buf_ptr[buffer_id].status);
		}
	}
}

// to snort
void rx_thread_0(struct channel *channel_ptr)
{
	int in_progress_count = 0, buffer_id = 0;
	int rx_counter = 0;
	int status;
	parsed_packet parsed_packet;
	int packet_size;
	int sleep_time_ms = 50;

	while(!stop){
		memset(channel_ptr->buf_ptr[buffer_id].buffer, 0, test_size);
		channel_ptr->buf_ptr[buffer_id].length = test_size;
		ioctl(channel_ptr->fd, START_XFER, &buffer_id);
		
		while(!stop){
			ioctl(channel_ptr->fd, FINISH_XFER, &buffer_id);
			if (channel_ptr->buf_ptr[buffer_id].status == channel_buffer::proxy_status::PROXY_NO_ERROR) {
				break;
			} 
			else {
				if (channel_ptr->buf_ptr[buffer_id].status == channel_buffer::proxy_status::PROXY_TIMEOUT){
					// printf("timeout\n");
					std::this_thread::sleep_for(std::chrono::milliseconds(sleep_time_ms));
					continue;
				}
				//printf("Proxy rx transfer error, # transfers %d, # completed %d, # in progress %d\n",
				//			num_transfers, rx_counter, in_progress_count);
				// exit(1);
				return;
			}
		}


		// send to snort (handle error status)
		// get size of packet by parsing
		parsed_packet = parse_packet((const u_char *)channel_ptr->buf_ptr[buffer_id].buffer);
		packet_size = SIZE_ETHERNET + parsed_packet.size_ip + parsed_packet.size_tcp + parsed_packet.size_payload;
		//printf("size_ip = %d, size_tcp = %d, size_payload = %d,  total = %d\n", parsed_packet.size_ip, parsed_packet.size_tcp, parsed_packet.size_payload, 
		//																	packet_size);
		print_payload((const u_char *)channel_ptr->buf_ptr[buffer_id].buffer, 100);
		status = pcap_inject(inject_snort_handle, channel_ptr->buf_ptr[buffer_id].buffer, packet_size);
		if (status == -1){
			//fprintf(stderr, "Error sending packet to snort: %s\n", pcap_geterr(inject_snort_handle));
		}
		
		buffer_id += BUFFER_INCREMENT;
		buffer_id %= RX_BUFFER_COUNT;
	}
}

// to egress
void rx_thread_1(struct channel *channel_ptr)
{
	int in_progress_count = 0, buffer_id = 0;
	int rx_counter = 0;
	int status;
	parsed_packet parsed_packet;
	int packet_size;

	while(!stop){
		memset(channel_ptr->buf_ptr[buffer_id].buffer, 0, test_size);
		channel_ptr->buf_ptr[buffer_id].length = test_size;
		ioctl(channel_ptr->fd, START_XFER, &buffer_id);
		
		while(!stop){
			ioctl(channel_ptr->fd, FINISH_XFER, &buffer_id);
			if (channel_ptr->buf_ptr[buffer_id].status == channel_buffer::proxy_status::PROXY_NO_ERROR) {
				break;
			} 
			else {
				if (channel_ptr->buf_ptr[buffer_id].status == channel_buffer::proxy_status::PROXY_TIMEOUT){
					// printf("timeout\n");
					continue;
				}
				//printf("Proxy rx transfer error, # transfers %d, # completed %d, # in progress %d\n",
				//			num_transfers, rx_counter, in_progress_count);
			}
		}

		// send to egress (handle error status)
		// get size of packet by parsing
		parsed_packet = parse_packet((const u_char *)channel_ptr->buf_ptr[buffer_id].buffer);
		packet_size = SIZE_ETHERNET + parsed_packet.size_ip + parsed_packet.size_tcp + parsed_packet.size_payload;
		status = pcap_inject(inject_egress_handle, channel_ptr->buf_ptr[buffer_id].buffer, packet_size);
		if (status == -1){
			//fprintf(stderr, "Error sending packet to egress: %s\n", pcap_geterr(inject_egress_handle));
		}
		
		buffer_id += BUFFER_INCREMENT;
		buffer_id %= RX_BUFFER_COUNT;
	}
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

	pthread_create(&tx_channels[0].tid, &tattr_tx, (void* (*)(void*))tx_thread, (void *)&tx_channels[0]);
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
	int max_channel_count = TX_CHANNEL_COUNT;

	printf("DMA proxy test\n");

	signal(SIGINT, sigint);

	if (argc != 4) {
		printf("Usage: dma-proxy-test <sniff_interface> <snort_v_interface> <egress_interface> \n");
		exit(EXIT_FAILURE);
	}

	char *s_dev, *i_dev, *e_dev;
	s_dev = argv[1];
	i_dev = argv[2];
	e_dev = argv[3];

// initiate pcaps
	// sniffer
	sniffer_handle = initiate_sniff_pcap(&s_fp, s_dev, "");
	if (sniffer_handle == NULL) {
		printf("Can't initiate sniff pcap\n");
		exit(EXIT_FAILURE);
	}

	// snort
	inject_snort_handle = initiate_inject_pcap(i_dev);
	if (inject_snort_handle == NULL) {
		printf("Can't initiate inject-snort pcap\n");
		exit(EXIT_FAILURE);
	}

	// egress
	inject_egress_handle = initiate_inject_pcap(e_dev);
	if (inject_egress_handle == NULL) {
		printf("Can't initiate inject-egress pcap\n");
		exit(EXIT_FAILURE);
	}

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

	/* Grab the start time to calculate performance then start the threads & transfers on all channels */

	setup_threads();

	for (i = 0; i < TX_CHANNEL_COUNT; i++) {
		pthread_join(tx_channels[i].tid, NULL);
		munmap(tx_channels[i].buf_ptr, sizeof(struct channel_buffer));
		close(tx_channels[i].fd);
	}

	printf("DMA proxy test complete\n");

	return 0;
}