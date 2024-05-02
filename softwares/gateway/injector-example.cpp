#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "pcap-utils.h"

#define DEBUG_LOGGING 1
#define SHOW_RAW_PAYLOAD 0

int packet_count;
char *dev;
pcap_t *handle;

void got_packet_2(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
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
	print_payload(packet, SIZE_ETHERNET + header->caplen);
	printf("\n");
	#endif
}

void self_receive_thread() {
    // receive packets with pcap_next_ex
    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_next_ex(handle, &header, &packet);
    // got_packet(NULL, header, packet);
    got_packet_2(NULL, header, packet);

}



int main(int argc, char **argv) {
    // arg1: inject-target (interface)
    // arg2: packet count to inject
    if (argc != 3) {
        printf("Usage: %s [interface] [packet_count]\n", argv[0]);
        printf("Current available interfaces:\n");
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Couldn't find available devices: %s\n", errbuf);
            return 1;
        }
        pcap_if_t *d;
        for (d = alldevs; d; d = d->next) {
            printf("%s\n", d->name);
        }
        return 1;
    }

    dev = argv[1];
    packet_count = atoi(argv[2]);

    handle = initiate_inject_pcap(dev);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't initiate pcap handle\n");
        return 1;
    }

    // craft a packet
    /*
    details:
    - ethernet header
        - destination MAC address: 00:11:22:aa:bb:cc
        - source MAC address: 99:88:77:FF:EE:DD
        - type: 0x0800 (IP)
    - IP header
        - version: 4
        - header length: 5
        - type of service: 0
        - total length: 40
        - identification: 0
        - flags: 0
        - fragment offset: 0
        - time to live: 64
        - protocol: 6 (TCP)
        - checksum: 0
        // network loopback
        - source IP address: 127.1.1.2 (hex: 7f 01 01 02)
        - destination IP address: 127.1.1.2
    - TCP header
        - source port: 12345
        - destination port: 80
        - sequence number: 0
        - acknowledgement number: 0
        - data offset: 5
        - flags: 0x02 (SYN)
        - window size: 65535
        - checksum: 0
        - urgent pointer: 0
    - payload
        - "Hello, world!"
    */

    u_char crafted_eth_h[] = {
        0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc, // destination MAC address
        0x99, 0x88, 0x77, 0xff, 0xee, 0xdd, // source MAC address
        0x08, 0x00 // type: 0x0800 (IP)
    };
    u_char crafted_ip_h[] = {
        0x45, 0x00, 0x00, 0x28, // version, header length, type of service, total length
        0x00, 0x00, 0x00, 0x00, // identification, flags, fragment offset
        0x40, 0x06, 0x00, 0x00, // time to live, protocol, checksum
        0x7f, 0x01, 0x01, 0x0a, // source IP address
        0x7f, 0x01, 0x01, 0x09  // destination IP address
    };
    u_char crafted_tcp_h[] = {
        0x30, 0x39, 0x00, 0x50, // source port, destination port
        0x00, 0x00, 0x00, 0x00, // sequence number
        0x00, 0x00, 0x00, 0x00, // acknowledgement number
        0x50, 0x02, 0xff, 0xff, // data offset, flags, window size
        0x00, 0x00, 0x00, 0x00  // checksum, urgent pointer
    };
    u_char crafted_payload[] = "Hello, world!";

    u_char packet[14 + 20 + 20 + 13];
    memcpy(packet, crafted_eth_h, 14);
    memcpy(packet + 14, crafted_ip_h, 20);
    memcpy(packet + 34, crafted_tcp_h, 20);
    memcpy(packet + 54, crafted_payload, 13);

    for (int i = 0; i < packet_count; i++) {
        if (pcap_inject(handle, packet, sizeof(packet)) == -1) {
            fprintf(stderr, "Couldn't inject packet: %s\n", pcap_geterr(handle));
            return 1;
        }
    }
}