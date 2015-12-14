#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
//will use later for shared memory operations
#include <sys/ipc.h>
#include <sys/shm.h>

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned short u_short;

char *myaddress;

bpf_u_int32 mask;
bpf_u_int32 net;

#define etheraddrsize 6

static int packetnumber;

const char *runmode;

struct trafficsample {
	u_int payloadbytestransferred;
	u_int icmpcount;
	u_int syncount;
	u_int tcpcount;
	u_int ackcount;
	u_int fincount;
	u_int number_of_sources;
	u_int udpcount;
	u_int unreachableportcount;
	u_int echorequests;
	u_int echoreplies;
	u_int localpingbroadcasts;
};

//some parameters that may be useful for a OCSVM
struct packetsample {
	int size;
	u_char source_port;
	u_char dest_port;
	u_char *payload;
	u_char *type;
};

typedef struct addressNode {
	char addressvalue[15];
	struct addressNode *next;
} srcnode;

struct suspiciousaddresses {
};

srcnode *head;
srcnode *temp;
srcnode *tail;

void getpktdata(const u_char *packet, struct trafficsample *instance);
void sniffpkts(pcap_t *handle, char *errbuff, char *traffictype);
void openerror(char *dev);
void printsample(struct trafficsample *s, char *traffictype);
void getAppData(u_char *payload, int *payloadsize,
		struct packetsample *packetdata);
void checkBlackList(char *srcaddr); //will use google's safe browsing API;
void add(char *srcaddr);
int findAddress(char *srcaddress);
void pingAddress(char *srcaddress); //perform some shallow analysis to check if the ip address is real or not by sending an echo request

typedef struct icmpheader {
#define echorequest 8
#define echoreply 0

	u_char icmptype;
	u_char icmpcode;
	u_short icmpchecksum;
} icmpheader;

typedef struct ethernetheader {
	u_char s_host[etheraddrsize];
	u_char d_host[etheraddrsize];
	u_char ethertype;
} ethernetheader;

typedef struct ipheader {
	u_char ver_headerlen;
	u_char servicetype;
	u_char totlen;
	u_short id;
	u_short flags_offset;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
	u_char ttl;
	u_char ipproto;
	u_short ipchecksum;
	//source addresses as unsigned 32 bit ints
	struct in_addr ipsrc, ipdest;
} ipheader;
//header length is the last 4 bits of this byte so mask all but these
#define ip_hl(ip) (((ip)->ver_headerlen) &0x0f)
//do a bitwise shift to extract the first 4 bits (all bits in original position prior to shift will be replaced by 0)
#define ip_ver(ip) (((ip)->ver_headerlen) >> 4)

typedef struct tcpheader {
	u_char s_port;
	u_char d_port;
	unsigned long tcpseq;
	unsigned long acknum;
	u_char offset_reserved;
#define offset(tcp) (((tcp)->offset_reserved) >>4)
	u_char tcpflags;
	/*
	 * this works by converting the set bits to a hex value. E.g the FIN flag being
	 * set is pattern 00000001 which converts to decimal 1, which is 0x01 in hex
	 */
#define FINflag 0x01
#define SYNflag 0x02
#define RSTflag 0x04
#define PSHflag 0x08
#define ACKflag 0x10
#define URGflag 0x20
	u_short tcpwinsize;
	u_short tcpchecksum;
	u_short urgptr;
} tcpheader;

/*
 * all UDP values are 2 bytes in length, therefore use unsigned shorts
 */
typedef struct udpheader {
	u_short srcport;
	u_short destport;
	u_short length;
	u_short checksum;
} udpheader;

void pingAddress(char *srcaddress) {

}

void sniffpkts(pcap_t *handle, char *errbuff, char *traffictype) {

	typedef struct trafficsample instance;
	double timetorecord = 10.00;
	struct pcap_pkthdr header;
	const u_char *packet;
	clock_t start;

	instance *newInstance = (struct trafficsample*) malloc(sizeof(instance));
	if (newInstance == NULL) {
		puts("memory allocation failure");
		exit(EXIT_FAILURE);
	} else {
		start = clock();
		puts("starting clock");
		while ((clock() - start) / CLOCKS_PER_SEC <= timetorecord) {
			packet = pcap_next(handle, &header);
			if (packet != NULL) {
				packetnumber++;
				getpktdata(packet, newInstance);
			}
		}
		if (runmode == "-train") {
			printsample(newInstance, traffictype);
		} else {
			//do some shared memory wizardry here

		}

		packetnumber = 0;
		memset(newInstance, 0, sizeof(instance));
		free(newInstance);
		head = NULL;
		temp = NULL;
		tail = NULL;
	}
}

void add(char *srcaddress) {
	srcnode *tem;
	tem = (srcnode*) malloc(sizeof(srcnode));
	strcpy(tem->addressvalue, srcaddress);
	tem->next = NULL;
	if (head == NULL) {
		head = tem;
		temp = head;
		tail = head;
	} else {
		temp = tem;
		tail->next = temp;
		tail = temp;
	}
	return;
}



//Extension

//void getAppData(u_char *payload, int *payloadsize,
//		struct packetsample *packetinfo) {
//	u_char *character;
//	u_char asciibuffer[*payloadsize];
//	character = payload;
//	int i = 0;
//	for (i = 0; i < *payloadsize; i++) {
//		asciibuffer[i] = *character;
//		character++;
//	}
//	packetinfo->payload = asciibuffer;
//}

int findAddress(char *srcaddress) {
	temp = head;
	while (temp != NULL) {
		if (strcmp(temp->addressvalue, srcaddress) == 0) {
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

//checks if any app is actually using the port by attempting to bind a new socket
//dumbed down version of icmp port unrechable for use with mininet
//NOTE: only applies to port usage on deployed machine
int checkportUsage(u_short destport) {
	int returnval = 0;
	struct sockaddr_in addr;
	int portNum = (int) destport;
	int testSock = socket(AF_INET, SOCK_STREAM, 0);
	addr.sin_port = htons(portNum);
	bzero((char*) &addr, sizeof(addr));
	if (bind(testSock, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		returnval = 1;
	} else {
		returnval = 0;
		close(testSock);
	}
	return returnval;
}

void getpktdata(const u_char *packet, struct trafficsample *instance) {
#define payloadlsize(tcp) (nthos(ip->totlen)-(size))
#define ethernetsize 14

	struct packetsample *packetAnalysis;
	packetAnalysis = (struct packetsample*) malloc(sizeof(struct packetsample));

	ethernetheader *ethhdr;
	ipheader *iphdr;
	tcpheader *tcphdr;
	icmpheader *icmphdr;
	udpheader *udp;

	ethhdr = (ethernetheader*) (packet);
	iphdr = (ipheader*) (packet + ethernetsize);

	int ip_header_size = ip_hl(iphdr) * 4;
	int total_packet_size = ntohs(iphdr->totlen);

	char *srcaddr = strdup(inet_ntoa(iphdr->ipsrc));
	char *destaddr = strdup(inet_ntoa(iphdr->ipdest));

	printf("packet source %s \n", srcaddr);
	printf("packet destination %s \n", destaddr);

	if (findAddress(srcaddr) == 0) {
		add(srcaddr);
		instance->number_of_sources++;
	}

//		packetAnalysis->size = totalsize;
	switch (iphdr->ipproto) {
	case IPPROTO_ICMP:
		icmphdr = (struct icmpheader*) (packet + ethernetsize + ip_header_size);
		switch (icmphdr->icmptype) {
//		case echorequest:
//			if (destaddrstring == broadcastadddress) {
//				instance->localpingbroadcasts++;
//			}
//			instance->echorequests++;
//			break;
		case echoreply:
			instance->echoreplies++;
			break;
		}
		return;
	case IPPROTO_TCP:
		instance->tcpcount++;
		tcphdr = (tcpheader*) (packet + ethernetsize + ip_header_size);
//			packetAnalysis->source_port = ntohs(tcphdr->s_port);
//			packetAnalysis->dest_port = ntohs(tcphdr->d_port);
		//u_char payload = (u_char*)(packet+ethernetsize+size_ip + tcp_hdrsize);
		if (tcphdr->tcpflags == SYNflag) {
			instance->syncount++;
		} else if (tcphdr->tcpflags == ACKflag) {
			instance->ackcount++;
		}
		return;
	case IPPROTO_UDP:
		udp = (udpheader*) (packet + ethernetsize + ip_header_size);
//			packetAnalysis->source_port = ntohs(udp->srcport);
//			packetAnalysis->dest_port = ntohs(udp->destport);
		instance->udpcount++;
		if (destaddr == myaddress) {
			if (checkportUsage(udp->destport) == 0) {
				instance->unreachableportcount++;
			}
		}

		return;
	case IPPROTO_IP:
		return;
	default:
		return;

	}
	free(packetAnalysis);
	free(srcaddr);
	free(destaddr);
}

void printsample(struct trafficsample *s, char *traffictype) {
	FILE *fp;
	fp = fopen("trainingdata", "a+");

	if (fp == NULL) {
		puts("could not open file");
		exit(1);
	}

	fprintf(fp, "%f,", (((double) s->tcpcount) / packetnumber) * 100); //percentage TCP
	fprintf(fp, "%f,", (((double) s->syncount) / packetnumber) * 100); //percentage SYN
	fprintf(fp, "%f,", (((double) s->ackcount) / packetnumber) * 100); //percentage ACK
	fprintf(fp, "%f,", (((double) s->fincount) / packetnumber) * 100); //percentage FIN
	fprintf(fp, "%f,", (((double) s->udpcount) / packetnumber) * 100); //percentage UDP
	fprintf(fp, "%d,", s->unreachableportcount); //number of unreachable port errors
	fprintf(fp, "%d,", s->number_of_sources); //number of unique source addresses
	fprintf(fp, "%d,", s->echorequests); //percentage of ICMP messages that were ping broadcasts
	fprintf(fp, "%d,", s->echoreplies); //number of echo replies
	fprintf(fp, "%d,", s->localpingbroadcasts); //number of pings sent to the broadcast address
	fprintf(fp, "%s", traffictype);
	fprintf(fp, "\n");
	fclose(fp);
	return;
}
void openerror(char *dev) {
	printf(
			"could not open device  %s. Ensure that root privileges are enabled \n",
			dev);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
#define samplesize 500
	struct in_addr myaddr;
	char *sniffdevice, *traffictype;
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const char *train = "-train";
	const char *live = "-live";

	sniffdevice = argv[1];
	runmode = argv[2];
	printf("running in %s mode \n", runmode);
	traffictype = argv[3];

	if (sniffdevice == NULL) {
		puts("enter a device to sniff on");
	} else {

		if (pcap_lookupnet(sniffdevice, &net, &mask, errbuff) == -1) {
			printf("could not get the netmask for this device %s \n", errbuff);
		} else {
			myaddr.s_addr = net;
			myaddress = strdup(inet_ntoa(myaddr));
		}
		handle = pcap_open_live(sniffdevice, BUFSIZ, 1, -1, errbuff);

		if (handle != NULL) {
			if (strcmp(runmode, train) == 0) {
				printf("gathering %d samples of data \n", samplesize);
				int i = 0;
				while (i < samplesize) {
					sniffpkts(handle, errbuff, traffictype);
					i++;
				}
				puts("finished sampling data");
			} else {
				if (strcmp(runmode, live) == 0) {
					puts("monitoring network traffic");
					while (1) {

						sniffpkts(handle, errbuff, traffictype);
					}

				}
			}
			pcap_close(handle);
		} else {
			openerror(sniffdevice);
		}

	}
	return 1;
}


