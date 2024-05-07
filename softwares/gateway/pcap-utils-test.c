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

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>

#include <arpa/inet.h>

#include "pcap-utils.h"

#define DEBUG_LOGGING 1
#define SHOW_RAW_PAYLOAD 0
#define USE_CALLBACK 0 // 1: use pcap_loop, 0: use pcap_next_ex

/* Ethernet ARP packet from RFC 826 */
typedef struct {
   uint16_t htype;   /* Format of hardware address */
   uint16_t ptype;   /* Format of protocol address */
   uint8_t hlen;    /* Length of hardware address */
   uint8_t plen;    /* Length of protocol address */
   uint16_t op;    /* ARP opcode (command) */
   uint8_t sha[ETH_ALEN];  /* Sender hardware address */
   uint32_t spa;   /* Sender IP address */
   uint8_t tha[ETH_ALEN];  /* Target hardware address */
   uint32_t tpa;   /* Target IP address */
} arp_ether_ipv4;

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
			printf("   Protocol: unknown->%d\n", read_ip->ip_p);
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

int main(int argc, char **argv)
{
	printf("mode: %d\n", USE_CALLBACK);
	char *dev = NULL;			/* capture device name */
	char filter_exp[256];
	int count = 0;

	/* check for capture device name on command-line */
	if (argc == 4) {
		dev = argv[1];
		strncpy(filter_exp, argv[2], sizeof(filter_exp));
		count = atoi(argv[3]);
	}
	else {
		printf("Usage: %s <device> <filter> <count>\n", argv[0]);
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
	printf("waiting for packet\n");
    while(count) {
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
		count--;

		char pktbuff[1000000];
		memset(pktbuff, 0, sizeof(pktbuff));
		memcpy(pktbuff, packet, header->caplen);

		int len = parse_packet_for_length(pktbuff);
		if (len != header->len) {
			printf("parsed len: %d, caplen: %d, actual len: %d\n", len, header->caplen, header->len);
			printf("%d######################Error: parsed len is not equal to actual len\n", len);
			print_payload(packet, header->len);
			got_packet(NULL, header, packet);
		}
		if (header->caplen != header->len) {
			printf("\t######################weird: %d, %d\n", header->caplen, header->len);
		}
    }
	#endif

    cleanup_pcap(handle, &fp);
	return 0;
}
