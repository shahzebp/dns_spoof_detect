struct Ether_header{
	u_char 		dest_host[6];
	u_char 		src_host[6];
	u_short 	ether_type;
};

//The stucture has been taken from following blog:
//http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/

struct DNS_header {
    unsigned short id;
 
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
 
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
 
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
}__attribute__((packed, aligned(1)));

struct DNS_question {
	unsigned short	q_type;
	unsigned short 	q_class;
}__attribute__((packed, aligned(1)));

struct DNS_answer {
  unsigned short name;
  unsigned short atype;
  unsigned short aclass;
  unsigned int  ttl;
  unsigned short RdataLen;
  unsigned int Rdata;
}__attribute__((packed, aligned(1)));

size_t IP_HDR_SIZE;
size_t UDP_HDR_SIZE;
size_t DNS_HDR_SIZE;
size_t ETHER_HDR_SIZE;

#define IP_SIZE 16