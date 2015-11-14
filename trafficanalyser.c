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

#define etheraddrsize 6

void sniffpkts(pcap_t *handle, char *errbuff);

void cleardata();

void startclassifier();

void getpktdata(const unsigned char *packet);

void openerror(char *dev);

struct instanceData{
	/*
	 * possible indicators of a SYN flood attack
	 * looking for a large number of SYN packets with small number of fin packets
	 * multiple source addresses could also indicate spoof style attack
	 */
	unsigned int syncount;
	unsigned int ackcount;
	unsigned int fincount;
	unsigned int numsources;
	/*
	 * some possible UDP flood indicators. Looking for a large number of UDP packets
	 * and ICMP destination unreachable messages
	 */
	unsigned int udpcount;
	unsigned int destunreachablecount;
	/*
	 * some possible ICMP flood indicators
	 * looking for a large number of ICMP echo requests
	 */
	unsigned int echorequests;
	/*
	 * some possible smurf attack related behaviour
	 * looking for a very large number of echo replies
	 * possible dest address of 255.255.255.255 for broadcasting echo request
	 */
	unsigned int echoreplies;
	unsigned int echorequestbroadcasts;
};

struct icmpheader{
	unsigned char icmptype;
	unsigned char icmpcode;
	unsigned short icmpchecksum;
};

struct ethernetheader{
	unsigned char s_host[etheraddrsize];
	unsigned char d_host[etheraddrsize];
	unsigned char ethertype;
};

struct ipheader{
	unsigned char ver_headerlen;
	unsigned char servicetype;
	unsigned char totlen;
	unsigned short id;
	unsigned short flags_offset;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
	unsigned char ttl;
	unsigned char ipproto;
	unsigned short ipchecksum;
	struct in_addr ipsrc;
	struct in_addr ipdest;
};
//header length is the last 4 bits of this byte so mask all but these
#define ip_hl(ip) (((ip)->ver_headerlen) &0x0f)
//do a bitwise shift to extract the first 4 bits (all bits in original position prior to shift will be replaced by 0)
#define ip_ver(ip) (((ip)->ver_headerlen) >> 4)

struct tcpheader{
	unsigned char s_port;
	unsigned char d_port;
	unsigned char tcpseq[4];
	unsigned char tcpacknum[4];
	unsigned char offset_reserved;
#define offset(tcp) (((tcp)->offset_reserved) >>4)
	unsigned char tcpflags;
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
#define ECEflag 0x40
#define CWRflag 0x80
	unsigned char tcpwinsize;
	unsigned char tcpchecksum;
	unsigned char urgptr;
};

void sniffpkts(pcap_t *handle, char *errbuff){

	struct pcap_pkthdr header;
	const unsigned char *packet;
	puts ("sniffing packets...");

	//FIX: make this a timed condition
	while (1){
		packet = pcap_next(handle, &header);
		//printf("packet length: %d \n", header.len);

		if (packet !=NULL){
			getpktdata(packet);
		}

	}

	pcap_close(handle);

}

void getpktdata(const unsigned char *packet){
#define ethernetsize 14
	struct ethernetheader *ethhdr;
	struct ipheader *iphdr;
	struct tcpheader *tcphdr;
	struct icmpheader *icmphdr;

	ethhdr = (struct ethernetheader*)(packet);
	iphdr = (struct ipheader*)(packet + ethernetsize);

	/*
	 * IHL usually split into 32 bit words. But we get the same result by multiplying the value by 4
	 */
	int size_ip = ip_hl(iphdr)*4;

	switch(iphdr->ipproto){
	case IPPROTO_ICMP:
		puts("protocol ICMP");
		icmphdr = (struct icmpheader*)(packet + ethernetsize + size_ip);
		//do some icmp analysis here
		return;
	case IPPROTO_TCP:
		tcphdr = (struct tcpheader*)(packet + ethernetsize + size_ip);
		switch(tcphdr->tcpflags){
		case SYNflag:
			puts("TCP SYN");
			break;
		case ACKflag:
			puts("TCP ACK");
			break;
		}
		return;
	case IPPROTO_UDP:
		puts("protocol UDP");
		return;
	case IPPROTO_IP:
		puts("protocol IP");
		return;
	default:
		puts("protocol other");
		return;

	}
}

/*
 * sniffer will close if handle cannot be created
 */

void openerror(char *dev){
	printf("could not open device  %s. Ensure that root privileges are enabled \n", dev);
	exit (EXIT_FAILURE);
}

int main(int argc, char *argv[]){
	char *sniffdevice;
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	sniffdevice = argv[1];

	if (sniffdevice==NULL){
		puts("please ensure that you specify a device");
		exit(EXIT_FAILURE);
	}else{
		printf("Device chosen: %s \n", sniffdevice);
		handle = pcap_open_live(sniffdevice, BUFSIZ, 1, 1000, errbuff);
		handle == NULL? openerror(sniffdevice): sniffpkts(handle, errbuff);
	}

}





