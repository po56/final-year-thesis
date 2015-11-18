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

typedef unsigned int u_int;
typedef unsigned char  u_char;
typedef unsigned short u_short;

#define etheraddrsize 6

void sniffpkts(pcap_t *handle, char *errbuff);

void startclassifier();

void openerror(char *dev);

struct instanceData{
	/*
	 * possible indicators of a SYN flood attack
	 * looking for a large number of SYN packets with small number of fin packets
	 * multiple source addresses could also indicate spoof style attack
	 */
	u_int syncount;
	u_int ackcount;
	u_int fincount;
	u_int unqiuesourcecount;
	/*
	 * some possible UDP flood indicators. Looking for a large number of UDP packets
	 * and ICMP destination unreachable messages. Large number of dest unreachable messages
	 * implies source ports being targeted that have no application listening
	 * per source information isnt particularly helpful since the ip address in this type of attack is usually spoofed
	 */
	u_int udpcount;
	u_int unreachableportcount;
	/*
	 * some possible ICMP flood indicators
	 * looking for a large number of ICMP echo requests
	 */
	u_int echorequests;
	/*
	 * some possible smurf attack relechorequests++;
			break;
		case echoreply:
			instance.echoreplies++;
			break;ated behaviour
	 * looking for a very large number of echo replies
	 * possible dest address of 255.255.255.255 for broadcasting echo request
	 */
	u_int echoreplies;
	u_int localpingbroadcasts;


};

void getpktdata(const u_char  *packet, struct instanceData *instance);

/*
 * method for testing that data has been gathered
 */

void printinstancedata(struct instanceData *instance);

struct icmpheader{
#define echorequest 8
#define echoreply 0
#define destinationunreachable 3
#define destportunreachable 3

	u_char  icmptype;
	u_char  icmpcode;
	u_short icmpchecksum;
};

//this information might be helpful for a slowloris style attack

struct peraddressflow{
	u_int bandwidthuse;
	u_int numberofconnections;

};

struct ethernetheader{
	u_char  s_host[etheraddrsize];
	u_char  d_host[etheraddrsize];
	u_char  ethertype;
};

struct ipheader{
	u_char  ver_headerlen;
	u_char  servicetype;
	u_char  totlen;
	u_short id;
	u_short flags_offset;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
	u_char  ttl;
	u_char  ipproto;
	u_short ipchecksum;
	//source addresses as unsigned 32 bit ints
	struct in_addr ipsrc;
	struct in_addr ipdest;
};
//header length is the last 4 bits of this byte so mask all but these
#define ip_hl(ip) (((ip)->ver_headerlen) &0x0f)
//do a bitwise shift to extract the first 4 bits (all bits in original position prior to shift will be replaced by 0)
#define ip_ver(ip) (((ip)->ver_headerlen) >> 4)

struct tcpheader{
	u_char  s_port;
	u_char  d_port;
	u_char  tcpseq[4];
	u_char  tcpacknum[4];
	u_char  offset_reserved;
#define offset(tcp) (((tcp)->offset_reserved) >>4)
	u_char  tcpflags;
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
	u_char  tcpwinsize;
	u_char  tcpchecksum;
	u_char  urgptr;
};
/*
 * all UDP values are 2 bytes in length, therefore use unsigned shorts
 */
struct udpheader{
	u_short srcport;
	u_short destport;
	u_short length;
	u_short checksum;
};


//void printinstancedata(struct instanceData *instance){
//	printf("number of SYN packets: %d \n", instance->syncount);
//	printf("number of ACK packets: %d \n", instance->ackcount);
//	printf("number of FIN packets: %d \n", instance->fincount);
//	printf("number of source addresses: %d \n", instance->unqiuesourcecount);
//	printf("number of UDP packets: %d \n", instance->udpcount);
//	printf("number of ping requests: %d \n", instance->echorequests);
//	printf("number of ping replies: %d \n", instance->echoreplies);
//	printf("number of ping requests sent to the broadcast address: %d \n", instance->localpingbroadcasts);
//	printf("number of port unreachable errors %d \n", instance->unreachableportcount);
//	//deallocate the memory after printing
//	memset(instance, 0, sizeof(instance));
//	free(instance);
//}


void sniffpkts(pcap_t *handle, char *errbuff){

	typedef struct instanceData instance;
	typedef struct timeval time;
	double timetorecord = 10.00;
	struct pcap_pkthdr header;
	const u_char  *packet;
	const u_char  *firstpacket;
	time startTime, currTime;
	clock_t start;

	puts ("sniffing packets...");
	//allocate some memory for the instance

	instance *newInstance = (struct instanceData*)malloc(sizeof(instance));

	if(newInstance==NULL){
		puts("memory allocation failure");
		exit(EXIT_FAILURE);
	}else{

	printf("allocated memory for a new timed instance \n");
	printf("capturing packets at %f second intervals \n", timetorecord);

	start = clock();
	while ((clock()-start)/CLOCKS_PER_SEC <= timetorecord){
		packet = pcap_next(handle, &header);
		if (packet !=NULL){
			getpktdata(packet,newInstance);

		}
	}



	printf("number of SYN packets: %d \n", newInstance->syncount);
	printf("number of ACK packets: %d \n", newInstance->ackcount);
	printf("number of FIN packets: %d \n", newInstance->fincount);
	printf("number of source addresses: %d \n", newInstance->unqiuesourcecount);
	printf("number of UDP packets: %d \n", newInstance->udpcount);
	printf("number of ping requests: %d \n", newInstance->echorequests);
	printf("number of ping replies: %d \n", newInstance->echoreplies);
	printf("number of ping requests sent to the broadcast address: %d \n", newInstance->localpingbroadcasts);
	printf("number of port unreachable errors %d \n", newInstance->unreachableportcount);
	//deallocate the memory after printing
	puts("finished recording, deallocating memory...");

	memset(newInstance, 0, sizeof(instance));
	free(newInstance);
	}
}


void getpktdata(const u_char  *packet, struct instanceData *instance){
#define ethernetsize 14
	typedef struct ethernetheader ethernetheader;
	typedef struct ipheader ipheader;
	typedef struct tcpheader tcpheader;
	typedef struct icmpheader icmpheader;
	typedef struct udpheader udpheader;

	ethernetheader *ethhdr;
	ipheader *iphdr;
	tcpheader *tcphdr;
	icmpheader *icmphdr;
	udpheader *udp;


	ethhdr = (ethernetheader*)(packet);
	iphdr = (ipheader*)(packet + ethernetsize);

	/*
	 * IHL usually split into 32 bit words. But we get the same result by multiplying the value by 4
	 */

	int size_ip = ip_hl(iphdr)*4;
	/*
	 * data structure for storing previously seen ipadresses
	 */
	switch(iphdr->ipproto){
	case IPPROTO_ICMP:
		icmphdr = (struct icmpheader*)(packet + ethernetsize + size_ip);

		switch (icmphdr->icmptype){
		case echorequest:
			//255.255.255.255.255 is the broadcast address for the local network
			//NEVER forwards packets to networks outside the local network, therefore risk of smurf limited to local hosts
			//checking for smurf related activity
			if(inet_ntoa(iphdr->ipdest)=="255.255.255.255.255"){
				instance->localpingbroadcasts++;
			}
			instance->echorequests++;
			break;
		case echoreply:
			instance->echoreplies++;
			break;
		case destinationunreachable:
			if (icmphdr->icmpcode==destportunreachable){
				instance->unreachableportcount++;
			}
			break;
		}
		return;
	case IPPROTO_TCP:
		tcphdr = (tcpheader*)(packet + ethernetsize + size_ip);
		switch(tcphdr->tcpflags){
		case SYNflag:
			instance->syncount++;
			break;
		case ACKflag:
			instance->ackcount++;
			break;
		case FINflag:
			instance->fincount++;
			break;
		}
		return;

	case IPPROTO_UDP:
		udp = (udpheader*)(packet + ethernetsize + size_ip);

		instance->udpcount++;
		return;
	case IPPROTO_IP:
		return;
	default:
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

	char *sniffdevice, *runmode;
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	sniffdevice = argv[1];
	runmode = argv[2];

	if (sniffdevice==NULL){
		puts("please ensure that you specify a device");
		exit(EXIT_FAILURE);
	}else{
		printf("Device chosen: %s \n", sniffdevice);
		handle = pcap_open_live(sniffdevice, BUFSIZ, 1, -1, errbuff);
		if (handle == NULL){
			openerror(sniffdevice);
		}else
			switch (runmode){
			case "train":
				int i = 0;
				while (i<500){
					puts ("capturing attack data");
					sniffpkts(handle, errbuff);
					i++;

				}
				break;
			case "live":
				while(1){
					puts("sniffing packets");
					sniffpkts(handle, errbuff);
				}
			}
			/*
			 * loop to capture packets indefinitley
			 */

			//capture 500 instances of attack data

		pcap_close(handle);
	}

}




