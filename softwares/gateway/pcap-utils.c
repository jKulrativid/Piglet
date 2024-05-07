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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/icmp6.h>

#include <net/ethernet.h>

#include <arpa/inet.h>

#include "pcap-utils.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define SIZE_ARP 28 + 18 // 28 bytes for ARP header, 18 bytes for padding to make it 46 bytes
#define SIZE_IPV6_HEADER 40

#define PCAP_TIMEOUT 1000 // doesn't seems useful for a non-blocking mode



/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}


/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{	

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

parsed_packet get_empty_packet() {
	parsed_packet parsed_packet;
	parsed_packet.ethernet = NULL;
	parsed_packet.ip = NULL;
	parsed_packet.tcp = NULL;
	parsed_packet.payload = NULL;
	parsed_packet.size_ip = 0;
	parsed_packet.size_tcp = 0;
	parsed_packet.size_payload = 0;
	return parsed_packet;
}

// still bug but nevermind
parsed_packet parse_packet(const u_char *packet) {
	parsed_packet parsed_packet = get_empty_packet();

	struct ether_header *ethernet;
	struct ip *ip;
	struct tcphdr *tcp;
	char *payload;
	int size_ip;
	int size_tcp;
	int size_payload;

	// parse ethernet
	ethernet = (struct ether_header*)(packet);
	parsed_packet.ethernet = ethernet;

	// parse ip
	ip = (struct ip*)(packet + SIZE_ETHERNET);
	size_ip = ip->ip_hl*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return parsed_packet;
	}
	parsed_packet.ip = ip;
	parsed_packet.size_ip = size_ip;

	// determine protocol
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			break;
		case IPPROTO_UDP:
			return parsed_packet;
		case IPPROTO_ICMP:
			return parsed_packet;
		case IPPROTO_IP:
			return parsed_packet;
		default:
			return parsed_packet;
	}

	// parse tcp
	tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = tcp->th_off * 4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return parsed_packet;
	}
	parsed_packet.tcp = tcp;
	parsed_packet.size_tcp = size_tcp;

	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	parsed_packet.payload = payload;
	parsed_packet.size_payload = size_payload;

	return parsed_packet;
}

/*
return the length of the packet
-1: error
-2: not supported -> just fwd to snort
*/
int parse_packet_for_length(const u_char *packet) {
	struct ether_header *ethernet;

	// parse ethernet
	ethernet = (struct ether_header*)(packet);
	switch (ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP:
			// printf("IP\n");
			// parse ip
			struct ip *ip = (struct ip*)(packet + SIZE_ETHERNET);
			switch (ip->ip_p) {
				case IPPROTO_TCP:
					goto handle_ip;
				case IPPROTO_UDP:
					goto handle_ip;
				case IPPROTO_IP:
					goto handle_ip;
					handle_ip:
					// printf("IP\n");
					int size_ip_header = ip->ip_hl*4;
					// printf("size_ip_len: %d\n", ntohs(ip->ip_len));
					if (size_ip_header < 20) {
						printf("   * Invalid IP header length: %u bytes\n", size_ip_header);
						return -1;
					}
					return ntohs(ip->ip_len) + SIZE_ETHERNET;
				default:
					return -2;
			}
		case ETHERTYPE_ARP:
			// printf("ARP\n");
			return SIZE_ARP + SIZE_ETHERNET;
		case ETHERTYPE_IPV6:
			// printf("IPv6\n");
			struct ip6_hdr *ip6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
			return SIZE_ETHERNET + SIZE_IPV6_HEADER + ntohs(ip6->ip6_plen);
		case ETHERTYPE_VLAN:
			// printf("VLAN\n");
			return SIZE_ETHERNET + 4;
		case ETHERTYPE_PUP:
			goto just_fwd;
		case ETHERTYPE_SPRITE:
			goto just_fwd;
		case ETHERTYPE_REVARP:
			goto just_fwd;
		case ETHERTYPE_AT:
			goto just_fwd;
		case ETHERTYPE_AARP:
			goto just_fwd;
		case ETHERTYPE_IPX:
			goto just_fwd;
		case ETHERTYPE_LOOPBACK:
			just_fwd:
			return -2;
		default:
			return -1;
	}
}

pcap_t* initiate_inject_pcap(char *dev) {
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	if (dev == NULL) {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			return NULL;
		}
	}

	/* print capture info */
	printf("Device: %s\n", dev);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, PCAP_TIMEOUT, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return NULL;
	}
	return handle;
}

pcap_t* initiate_sniff_pcap(struct bpf_program *fp,  char *dev, const char filter_exp[]) {
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */
	
	if (dev == NULL) {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			return NULL;
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, PCAP_TIMEOUT, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return NULL;
	}

	// Set the handle to non-blocking mode
    if (pcap_setnonblock(handle, 1, errbuf) != 0) {
        fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
        pcap_close(handle);
        return NULL;
    }

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return NULL;
	}

	/* compile the filter expression */
	if (pcap_compile(handle, fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		return NULL;
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		return NULL;
	}

	// /* now we can set our callback function */
	// pcap_loop(handle, num_packets, callback, NULL);
	printf("handle address2: %p\n", handle);
	return handle;
}

void cleanup_pcap(pcap_t *handle, struct bpf_program *fp) {
	pcap_freecode(fp);
	pcap_close(handle);
	printf("\nCapture complete.\n");
}