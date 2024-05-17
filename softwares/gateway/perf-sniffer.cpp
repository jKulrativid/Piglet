#define APP_NAME		"perf-sniffer"
#define APP_DESC		"sniff packet from ethernet device then send to dma - derived Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <chrono>

#include <thread>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include "pcap-utils.h"

typedef std::chrono::high_resolution_clock Clock;

#define DEBUG_LOGGING 1
#define SHOW_RAW_PAYLOAD 1
#define USE_CALLBACK 0 // 1: use pcap_loop, 0: use pcap_next_ex
#define CHECK_MATCH_PACKETS 1

int count = 0;
int stop = 0;


void sigint(int a)
{
	stop = 1;
}

void
print_app_usage(void);

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface] [filter_exp] [pkt1_length] [pkt1_required] [pkt2_length] [pkt2_required] [timeout]\n", APP_NAME);
	printf("timeout: 0 for no timeout\n");
	printf("\n");

return;
}

void got_packet_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("got packet no.:%d\n", ++count);
	parsed_packet parsed_packet = parse_packet(packet);
	
	#if DEBUG_LOGGING
	static int count = 1;                   /* packet counter */
	printf("\nPacket number %d:\n", count);
	count++;

	printf("MAC src: %s\n", ether_ntoa((struct ether_addr *)parsed_packet.ethernet->ether_shost));
	printf("MAC dst: %s\n", ether_ntoa((struct ether_addr *)parsed_packet.ethernet->ether_dhost));

	if (parsed_packet.size_ip != 0) {
		printf("IP src: %s\n", inet_ntoa(parsed_packet.ip->ip_src));
		printf("IP dst: %s\n", inet_ntoa(parsed_packet.ip->ip_dst));
		printf("IP protocol: %d\n", parsed_packet.ip->ip_p);
	}

	if (parsed_packet.size_tcp != 0) {
		printf("TCP src port: %d\n", ntohs(parsed_packet.tcp->th_sport));
		printf("TCP dst port: %d\n", ntohs(parsed_packet.tcp->th_dport));
	}

	if (parsed_packet.size_payload != 0) {
		printf("Payload (%d bytes):\n", parsed_packet.size_payload);
		print_payload((const u_char *)parsed_packet.payload, parsed_packet.size_payload);
	}
	#endif

	#if SHOW_RAW_PAYLOAD
	// print raw payload data
	printf("Payload (%d bytes), cap(%d):\n", header->len, header->caplen);
	printf("size_eth = %d, ", SIZE_ETHERNET);
	printf("size_ip = %d, size_tcp = %d, size_payload = %d,  total = %d\n", parsed_packet.size_ip, parsed_packet.size_tcp, parsed_packet.size_payload, 
																			SIZE_ETHERNET + parsed_packet.size_ip + parsed_packet.size_tcp + parsed_packet.size_payload);
	print_payload(packet, header->len);
	printf("\n");
	#endif
	printf("waiting for packet\n");
	
}

int main(int argc, char **argv)
{

	signal(SIGINT, sigint);
	std::cout << "mode: " << USE_CALLBACK << std::endl;
	std::cout << "argc: " << argc << std::endl;
	char *dev = NULL;			/* capture device name */
	char filter_exp[256];
	int pkt_lengths[] = {0, 0};
	int pkt_requireds[] = {0, 0};
	int timeout = 0;

	/* check for capture device name on command-line */
	if(argc == 7) {
		dev = argv[1];
		strncpy(filter_exp, argv[2], sizeof(filter_exp));
		pkt_lengths[0] = atoi(argv[3]);
		pkt_requireds[0] = atoi(argv[4]);
		pkt_lengths[1] = atoi(argv[5]);
		pkt_requireds[1] = atoi(argv[6]);
	}
	else if (argc == 8) {
		dev = argv[1];
		strncpy(filter_exp, argv[2], sizeof(filter_exp));
		pkt_lengths[0] = atoi(argv[3]);
		pkt_requireds[0] = atoi(argv[4]);
		pkt_lengths[1] = atoi(argv[5]);
		pkt_requireds[1] = atoi(argv[6]);	
		timeout = atoi(argv[7]);
	}
	else {
		print_app_usage();
		exit(EXIT_FAILURE);
	}

	// filter
    pcap_t *handle;				
    struct bpf_program fp;		

	// override filter
	sprintf(filter_exp, "");
    
    printf("handle address1: %p\n", handle);
    handle = initiate_sniff_pcap(&fp, dev, filter_exp);
    printf("handle address3: %p\n", handle);
	if (handle == NULL) {
		printf("Error status\n");
		exit(EXIT_FAILURE);
	}
    
	#if USE_CALLBACK
	printf("waiting for packet\n");
	pcap_loop(handle, 0, got_packet_2, NULL);
	#else

	// int pkt1_length = 1053;
	// int count_pkt1 = 0;
	// int pkt2_length = 253;
	// int count_pkt2 = 0;
	int pkt_counts[] = {0, 0};
	bool pkt_completes[] = {false, false};
	if (pkt_requireds[0] == 0) pkt_completes[0] = true;
	if (pkt_requireds[1] == 0) pkt_completes[1] = true;
	int COUNT_CASES = 2;

	bool is_timer_started = 0;
	bool completed;

	auto start_time = Clock::now();
	auto end_time = Clock::now();

	// create a thread to stop the loop after timeout if timeout > 0
	if (timeout > 0) {
		std::thread t([&](){
		std::this_thread::sleep_for(std::chrono::seconds(timeout));
			stop = 1;
		});
		t.detach();
	}

    while(!stop) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int status = pcap_next_ex(handle, &header, &packet);
		if (status == -1) {
			// printf("Error reading the packets: %s\n", pcap_geterr(handle));
			break;
		} 
		if (status == 0) {
			// printf("Receive timeout\n");
			continue;
		}

		// if (header->len == pkt1_length){
		// 	printf("packet1 no.:%d\n", ++count_pkt1);
		// 	is_timer_started = true;
		// }
		// if (header->len == pkt2_length){
		// 	printf("packet2 no.:%d\n", ++count_pkt2);
		// 	is_timer_started = true;
		// }
		for (int i = 0; i < COUNT_CASES; i++) {
			if (header->len == pkt_lengths[i]) {
				// printf("packet%d no.:%d\n", i+1, ++pkt_counts[i]);
				++pkt_counts[i];
				if (!is_timer_started){
					is_timer_started = true;
					start_time = Clock::now();
					printf("timer begin\n");
				}

				if (pkt_counts[i] == pkt_requireds[i]) {
					pkt_completes[i] = true;
				}
				end_time = Clock::now();
			}
		}

		completed = true;
		for (int i = 0; i < COUNT_CASES; i++) {
			if (!pkt_completes[i]) {
				completed = false;
				break;
			}
		}
		if (completed) goto exit_loop;


    }
	exit_loop:
	// duration nanosecond
	auto duration = (end_time - start_time);
	double dur_seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() / 1e9;
	std::cout << "Duration: " << dur_seconds << " s, " << std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count() << " ns\n"; 

	for (int i = 0; i < COUNT_CASES; i++) {
		printf("overall pkt%d count = %d\n", i+1, pkt_counts[i]);
	}

	int bytes_transferred = 0;
	for (int i = 0; i < COUNT_CASES; i++) {
		bytes_transferred += pkt_counts[i] * pkt_lengths[i];
	}
	printf("Total bytes transferred: %d\n", bytes_transferred);

	double throughput = ((double)bytes_transferred) * 8 / dur_seconds; // in bits per second
	// printf("Throughput: %llf bps\n", throughput);
	// printf("Throughput: %llf Kbps\n", throughput / 1000);
	// printf("Throughput: %llf Mbps\n", throughput / 1000000);

	std::cout << "Throughput: " << throughput << " bps\n";
	std::cout << "Throughput: " << throughput / 1000 << " Kbps\n";
	std::cout << "Throughput(Mbps): " << throughput / 1000000 << " Mbps\n";

	// printf("overall pkt1 count = %d\n", count_pkt1);
	// printf("overall pkt2 count = %d\n", count_pkt2);

	// packet per second
	double pkt_per_second = ((double)pkt_counts[0] + pkt_counts[1]) / dur_seconds;
	std::cout << "Packet per second: " << pkt_per_second << " pps\n";

	#endif

    cleanup_pcap(handle, &fp);
	return 0;
}
