#ifndef PCAP_UTILS_H
#define PCAP_UTILS_H

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef SIZE_ETHERNET 
	#define SIZE_ETHERNET 14
#endif

#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN 6
#endif


typedef struct {
    struct ether_header *ethernet;
    struct ip *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    char *payload;
    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;
} parsed_packet;


void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

pcap_t* initiate_sniff_pcap(struct bpf_program *fp,  char *dev, const char filter_exp[]);

pcap_t* initiate_inject_pcap(char *dev);

void cleanup_pcap(pcap_t *handle, struct bpf_program *fp);

parsed_packet parse_packet(const u_char *packet);

int parse_packet_for_length(const u_char *packet);

parsed_packet get_empty_packet();

#endif /* PCAP_UTILS_H */
