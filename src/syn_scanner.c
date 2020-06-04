/**
 * Sends a TCP-SYN packet to an ip address and port.
 *
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define RECVPORT "64321"

/*
 * "Computing the Internet Checksum"
 * https://tools.ietf.org/html/rfc1071
 */

struct pseudo_checksum_header {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t padding;
	uint8_t protocol;
	uint16_t tcp_length;
};

uint16_t checksum(void *data, size_t count)
{
	uint16_t *ptr = (uint16_t *) data;
	uint32_t sum = 0;

	while (count > 1) {
		sum += *ptr++;
		count -= 2;
	}

	if (count > 0)
		sum += *((unsigned char *) ptr);

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

uint16_t tcp_compute_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header)
{
	struct pseudo_checksum_header phdr;
	char *pseudogram;
	size_t pseudogram_length;
	uint16_t csum;

	phdr.saddr = ip_header->saddr;
	phdr.daddr = ip_header->daddr;
	phdr.padding = 0;
	phdr.protocol = ip_header->protocol;
	phdr.tcp_length = htons(sizeof(struct tcphdr));

	pseudogram_length = sizeof(struct pseudo_checksum_header) + sizeof(struct tcphdr);

	// if there is an internal error 0 is returned as checksum intentionally
	if ((pseudogram = (char *) malloc(pseudogram_length)) == NULL)
		return 0;

	// compute checksum over: pseudo header + tcp header
	memcpy(pseudogram, &phdr, sizeof(struct pseudo_checksum_header));
	memcpy(pseudogram + sizeof(struct pseudo_checksum_header), tcp_header, sizeof(struct tcphdr));

	csum = checksum(pseudogram, pseudogram_length);

	free(pseudogram);

	return htons(csum);
}

/* Creates a RAW socket */
int create_socket(char *dest_ip, struct addrinfo **target)
{
	// TODO: copy result and freeaddrinfo()

	struct addrinfo hints, *result;
	int return_value;
	int set_on = 1;
	int sockfd;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_TCP;

	*target = NULL;

	if ((return_value = getaddrinfo(dest_ip, NULL, &hints, &result)) != 0) {
		fprintf(stderr, "[!] getaddrinfo() failed: %s\n", gai_strerror(return_value));
		return -1;
	}

	for (struct addrinfo *p = result; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("[!] socket() error");
			continue;
		}

		*target = p;
		break;
	}

	if (*target == NULL) {
		fprintf(stderr, "[!] creating socket() failed\n");
		return -1;
	}

	// set socket to send an IP header already included in the given payload:
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (const char *) &set_on, sizeof(set_on)) == -1) {
		perror("[!] setsockopt() failed");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

char *get_source_ip(int sockfd, char *interface)
{
	static struct ifreq ifreq_ip;
	memset(&ifreq_ip, 0,sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name, interface, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFADDR, &ifreq_ip);

	return inet_ntoa(((struct sockaddr_in *) &(ifreq_ip.ifr_addr))->sin_addr);
}

void craft_syn_packet(struct iphdr *ip_header, struct tcphdr *tcp_header, char *saddr, char *sport, char *daddr, char *dport)
{
	// Fill IP header:
	ip_header->version = 4;
	ip_header->ihl = 5;
	ip_header->tos = 0;
	ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ip_header->id = 0; // let kernel assign id
	ip_header->frag_off = 0;
	ip_header->ttl = 255;
	ip_header->protocol = IPPROTO_TCP;
	ip_header->check = 0; // let kernel compute ip checksum
	ip_header->saddr = inet_addr(saddr);
	ip_header->daddr = inet_addr(daddr);

	// Fill TCP Header:
	tcp_header->source = htons(atoi(sport));
	tcp_header->dest = htons(atoi(dport));
	tcp_header->seq = htons(0); // htons((uint16_t) 12345);
	tcp_header->ack_seq = htons(0);
	tcp_header->doff = 5;
	tcp_header->urg = 0;
	tcp_header->ack = 0;
	tcp_header->psh = 0;
	tcp_header->rst = 0;
	tcp_header->syn = 1;
	tcp_header->fin = 0;
	tcp_header->window = htons((uint16_t) -1); // maximum value possible
	tcp_header->check = htons(tcp_compute_checksum(ip_header, tcp_header));
}

int receive_syn_response(int sockfd, uint32_t daddr, char *sport)
{
	char msg[1024];
	int msglen;

	while ((msglen = recv(sockfd, msg, 1024, 0)) > 0) {
		if ((size_t) msglen < (sizeof(struct iphdr) + sizeof(struct tcphdr)))
			continue;

		struct iphdr *ip_header = (struct iphdr *) msg;
		struct tcphdr *tcp_header = (struct tcphdr *) (msg + 20);

		if (daddr == ip_header->saddr && ntohs(tcp_header->dest) == atoi(sport))
			return tcp_header->rst != 1;
	}

	return -1;
}

/* Returns 0 if the port seems to be closed, 1 if open, -1 on errors. */
int syn_scan(int sockfd, struct addrinfo *target, char *saddr, char *sport, char *daddr, char *dport)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;

	char *packet;
	size_t packet_length = sizeof(struct iphdr) + sizeof(struct tcphdr);

	if ((packet = (char *) malloc(packet_length)) == NULL) {
		perror("[!] malloc() failed");
		return -1;
	}

	memset(packet, 0, packet_length);

	ip_header = (struct iphdr *) packet;
	tcp_header = (struct tcphdr *) (packet + sizeof(struct iphdr));

	craft_syn_packet(ip_header, tcp_header, saddr, sport, daddr, dport);

	if (sendto(sockfd, packet, packet_length, 0, target->ai_addr, target->ai_addrlen) == -1) {
		free(packet);
		perror("[!] sendto() failed");
		return -1;
	}

	free(packet);
	return receive_syn_response(sockfd, ip_header->daddr, sport);
}

int main(int argc, char **argv)
{
	int sockfd;
	struct addrinfo *target;
	char *source_ip;

	char *target_ip, *target_port, *interface;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <interface> <target ip> <target port>\n", argv[0]);
		return -1;
	}

	interface = argv[1];
	target_ip = argv[2];
	target_port = argv[3];

	if ((sockfd = create_socket(target_ip, &target)) == -1) {
		return -1;
	}

	source_ip = get_source_ip(sockfd, interface);

	switch (syn_scan(sockfd, target, source_ip, RECVPORT, target_ip, target_port)) {
		case 0:
			printf("closed\n");
			break;
		case 1:
			printf("open\n");
			break;
		case -1:
			fprintf(stderr, "error\n");
			break;
	}

	close(sockfd);

	return 0;
}
