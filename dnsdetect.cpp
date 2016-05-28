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
#include <vector>

#include "dns_common.hpp"

using namespace std;		

std::map <int, vector<string> > history;	

struct DNS_header * extract_dns_data(const u_char *packet) {

	struct Ether_header * ether = (struct Ether_header*)(packet);

	struct iphdr * ip = (struct iphdr*)(((char*) ether) + ETHER_HDR_SIZE);
	unsigned int  ip_header_size = ip->ihl * 4;
	
	struct udphdr * udp = (struct udphdr *)(((char*) ip) + ip_header_size);
	
	struct DNS_header * dns_hdr = (struct DNS_header*)(((char*) udp) + UDP_HDR_SIZE);

	return dns_hdr;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
			const u_char *packet){

	unsigned int i = 1, j = 0, k;
	unsigned int size;
	struct DNS_header *dns_hdr = extract_dns_data(packet);
	
	char *curr = (char *)((char*) dns_hdr) + 12;	
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
	
	int offset = 12 + strlen(curr) + 1 + 4;
	
	struct DNS_answer *reader = (struct DNS_answer *)( ((char *)dns_hdr) + offset);

	int current_id = ntohs(dns_hdr->id);
	
	char buffer[INET_ADDRSTRLEN];
	
	if (history.find(current_id) == history.end()) {
		vector<string> ip_list;
		for (int i = 0; i < ntohs(dns_hdr->ans_count); i++){
			
			inet_ntop(AF_INET, &(reader->Rdata), buffer, INET_ADDRSTRLEN);
			buffer[INET_ADDRSTRLEN] = '\0';
			
			ip_list.push_back(string(buffer));
			reader = (struct DNS_answer *)( ((char *)reader) + 16);
		}
		history.insert(pair<int, vector<string> > (current_id, ip_list));
	} else {
		fprintf(stderr, "DNS poisoning attempt\n");
		fprintf(stderr, "TXID %d Request %s\n", current_id, request);
		fprintf(stderr, "Answer 1: ");
		std::vector<string> ip_vec = history[current_id];
		for(vector<string>::const_iterator i = ip_vec.begin(); i != ip_vec.end(); ++i) {
    		fprintf(stderr, "%s  ", (*i).c_str());
		}

		fprintf(stderr, "\n");
		fprintf(stderr, "Answer 2: ");

		for (int i = 0; i < ntohs(dns_hdr->ans_count); i++){
			char buffer[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(reader->Rdata), buffer, INET_ADDRSTRLEN);
			fprintf(stderr, "%s  ", buffer);
			reader = (struct DNS_answer *)( ((char *)reader) + 16);
		}

		fprintf(stderr, "\n");
	}
}

int main(int argc, char **argv){
	
	string filter, expression = "";

	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	pcap_t *descr;
	char *pcap_file = NULL;

	int c;
	char *spoof_file = NULL;
	char *dev = NULL;	 

    bpf_u_int32 maskp;
    bpf_u_int32 netp;

	while ((c = getopt (argc, argv, "i:r:h?")) != -1) {
		switch(c) {
			case 'i':
					dev = optarg;
					break;
			case 'r':
					 pcap_file = (char *)malloc(256);
                	memset(pcap_file, 0, 256);
                	strcpy(pcap_file, optarg);
                	break;
			default:
					printf("Wrong Usage\n");	
					break;
		}
	}

	if (argc > optind)
		expression = argv[optind];
	
	IP_HDR_SIZE 	=  sizeof(struct ip);
	UDP_HDR_SIZE 	=  sizeof(struct udphdr);
	DNS_HDR_SIZE	=  sizeof(struct DNS_header);
	ETHER_HDR_SIZE	=  sizeof(struct Ether_header);

	printf("Initializing\n");
	
	if (expression == "")
		filter = "udp and src port domain";
	else
		filter = "udp and src port domain and " + expression;

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	if (pcap_file) {
        descr = pcap_open_offline_with_tstamp_precision(pcap_file, 1, errbuf);
    } else {

        if (NULL == dev)
            dev = pcap_lookupdev(errbuf);

        if(dev == NULL) {
            fprintf(stderr, "%s\n", errbuf);
            exit(1);
        }

        pcap_lookupnet(dev, &netp, &maskp, errbuf);

		descr = pcap_open_live(dev, 1500, 1, 0, errbuf);
		printf("Device - %s\n", dev);
	}
	

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