#define APP_NAME		"piglet-pcap"
#define APP_DESC		"sniff packet from ethernet device then send to dma - derived Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include "pcap-utils.h"

#define DEBUG_LOGGING 1
#define SHOW_RAW_PAYLOAD 1
#define USE_CALLBACK 0 // 1: use pcap_loop, 0: use pcap_next_ex

int count = 0;

void
print_app_usage(void);

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	/* declare pointers to packet headers */
	const struct ether_header *read_ethernet;  /* The ethernet header [1] */
	const struct ip *read_ip;              /* The IP header */
	const struct tcphdr *read_tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;

	#if DEBUG_LOGGING
	static int count = 1;                   /* packet counter */
	printf("\nPacket number %d:\n", count);
	count++;
	#endif

	/* define ethernet header */
	read_ethernet = (struct ether_header*)(packet);

	/* define/compute ip header offset */
	read_ip = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = (read_ip->ip_hl)*4;
	
	
	
	#if DEBUG_LOGGING
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(read_ip->ip_src));
	printf("         To: %s\n", inet_ntoa(read_ip->ip_dst));

	/* determine protocol */
	switch(read_ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	# endif

	/*
	 *  OK, this packet is TCP.
	 */

	/* define/compute tcp header offset */
	read_tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = read_tcp->th_off * 4;
	
	#if DEBUG_LOGGING
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(read_tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(read_tcp->th_dport));
	#endif

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(read_ip->ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	#if DEBUG_LOGGING
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	#endif

	#if SHOW_RAW_PAYLOAD
	// print raw payload data
	printf("Payload (%d bytes), cap(%d):\n", header->len, header->caplen);
	printf("size_eth = %d, ", SIZE_ETHERNET);
	printf("size_ip = %d, size_tcp = %d, size_payload = %d,  total = %d\n", size_ip, size_tcp, size_payload, 
																			SIZE_ETHERNET + size_ip + size_tcp + size_payload);
	print_payload(packet, SIZE_ETHERNET + header->caplen);
	printf("\n");
	#endif

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
	printf("mode: %d\n", USE_CALLBACK);
	char *dev = NULL;			/* capture device name */
	char filter_exp[256];

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc == 3) {
		dev = argv[1];
		strncpy(filter_exp, argv[2], sizeof(filter_exp));
	}
	else if (argc > 3) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		print_app_usage();
		exit(EXIT_FAILURE);
	}

	// filter
    pcap_t *handle;				
    struct bpf_program fp;		
    
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
    while(true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int status = pcap_next_ex(handle, &header, &packet);
		if (status == -1) {
			printf("Error reading the packets: %s\n", pcap_geterr(handle));
			break;
		} 
		if (status == 0) {
			// printf("Receive timeout\n");
			continue;
		}
        // got_packet(NULL, header, packet);
		got_packet_2(NULL, header, packet);
    }
	#endif

    cleanup_pcap(handle, &fp);
	return 0;
}
