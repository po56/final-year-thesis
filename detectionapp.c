#include <pcap.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "detectionFunctions.h"
#include <pthread.h>

#define traceSize 9
#define ethersize 14

char *goodSource;

const char *types[] = { "SYN FLOOD", "UDP FLOOD", "ICMP FLOOD", "SMURF ATTACK",
		"SLOW HTTP", "LAYER 7 ATTACK", "NORMAL TRAFFIC" };
pcap_t *handle;

struct listNode {
	char value[15];
	struct listNode *next;
};


struct listNode *rootNode;
struct listNode *temp;

void createReport(int classificationResult, time_t currentTime) {
	const char *threat_type;

	switch (classificationResult) {
	case 2:
		threat_type = types[0];
		break;
	case 3:
		threat_type = types[1];
		break;
	case 4:
		threat_type = types[2];
		break;
	case 5:
		threat_type = types[3];
		break;
	case 6:
		threat_type = types[4];
		break;
	default:
		threat_type = NULL;
	}
	struct tm *timestring = localtime(&currentTime);

	printf(
			"A THREAT HAS BEEN DETECTED \n details \n type: %s \n time: %s \n suspect trace: \n",
			threat_type, asctime(timestring));
}
//credit to binary tides for this function
unsigned short in_cksum(unsigned short *ptr, int nbytes) {
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) &oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

int checkExistance(char *address) {
	temp = rootNode;
	while (temp != NULL) {
		if (strcmp(temp->value, address) == 0) {
			return 1;
		}
		temp = temp->next;
	}
	return 0;
}

void addressPrinter() {
	printf("========ADDRESSES FOR CURRENT TRACE====== \n");
	temp = rootNode;
	while (temp != NULL) {
		printf("address: %s \n", temp->value);
		temp = temp->next;
	}
	printf("========================================= \n");

}

void addNode(char *value) {

	struct listNode *new = (struct listNode*) malloc(sizeof(struct listNode));
	strcpy(new->value, value);
	new->next = NULL;
	if (rootNode == NULL) {
		rootNode = new;
		temp = rootNode;
	} else {
		temp = rootNode;
		while (temp->next != NULL) {
			temp = temp->next;
		}
		temp->next = new;
	}

}

double averageRTT(double times[], int nSamples, int iterator) {

	if (iterator == nSamples - 1) {
		return times[iterator];
	}
	if (iterator == 0) {
		return ((times[iterator] + averageRTT(times, nSamples, iterator + 1))
				/ nSamples);
	}
	return (times[iterator] + averageRTT(times, nSamples, iterator + 1));
}

void *getPingStats(void *args) {
#define loss(X,Y)(X/Y)
	char *data = "testping";

	struct PingArgs *arguments = args;

	char *chosenSource = arguments->sourceAddress;

	struct timedTrace *trace = arguments->trace;

	unsigned char *sentpacket, *recievedpacket;
	double avg;
	struct timeval sndTime, recvTime, timeOut;
	struct sockaddr_in to;
	struct icmphdr icp;
	int n_transmitted = 0, n_to_transmit = 5, nLost = 0, ID = getpid() & 0xFFFF,
			sockfd, successful_pings;
	double times[5] = { 0 };
	timeOut.tv_sec = 10;
	timeOut.tv_usec = 0;
	to.sin_addr.s_addr = inet_addr(chosenSource);
	to.sin_family = AF_INET;

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		fprintf(stderr, "could not create socket \n");
	}

	to.sin_addr.s_addr = inet_addr(chosenSource);
	to.sin_family = AF_INET;
	memset(&to.sin_zero, 0, sizeof(to.sin_zero));

	sentpacket = (unsigned char*) malloc(IP_MAXPACKET * sizeof(unsigned char));
	recievedpacket = (unsigned char*) malloc(IP_MAXPACKET);

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeOut,
			sizeof(timeOut)) < 0) {
		fprintf(stderr, "could not set socket option \n");
	}

	while (n_transmitted < n_to_transmit) {
		icp.code = 0;
		icp.type = ICMP_ECHO;
		icp.un.echo.sequence = n_transmitted + 1;
		icp.un.echo.id = ID;
		icp.checksum = 0;

		memcpy(sentpacket, &icp, 8);
		//and also the icmp data
		memcpy(sentpacket + 8, data, strlen(data));
		//calculate the checksum
		icp.checksum = in_cksum((unsigned short*) sentpacket, 8 + strlen(data));
		//and update the packet
		memcpy(sentpacket, &icp, 8);

		if (sendto(sockfd, sentpacket, 8 + strlen(data), 0,
				(struct sockaddr*) &to, sizeof(to)) < 0) {
			perror("could not send");
		} else {
			gettimeofday(&sndTime, NULL);
		}

		if (recvfrom(sockfd, recievedpacket,
				sizeof(struct icmphdr) + strlen(data), 0, NULL,
				(socklen_t*) sizeof(struct sockaddr)) >= 0) {
			gettimeofday(&recvTime, NULL);
			struct iphdr *recievedip = (struct iphdr*) (recievedpacket);
			struct icmphdr *receivedicmp = (struct icmphdr*) (recievedpacket
					+ (recievedip->ihl * 4));

			if (receivedicmp->type == ICMP_ECHOREPLY) {
				double timeTaken = (recvTime.tv_usec - sndTime.tv_usec);
				times[n_transmitted] = timeTaken;
				//this works on mininet as the controller becomes so overwhelemed it cannot find a suitable route to the host
			} else if (receivedicmp->type == 3) {
				nLost++;
			}

		} else {
			//if there was no data recieved from the source, implies the request timed out.
			perror("something went wrong when trying to receive: ");
			nLost++;
		}

		n_transmitted++;
	}

	trace->ping_packet_loss = loss((double )nLost, (double )n_transmitted);

	if ((successful_pings = n_transmitted - nLost) < 1) {
		avg = -1.00;
	} else {
		double newTimes[successful_pings];
		bzero(&newTimes, 5 * sizeof(double));
		double *all_tms = times;
		double *successful_png_tms = newTimes;

		int j = 0;
		for (j = 0; j < n_to_transmit; j++) {
			if (times[j] > 0) {
				memcpy(successful_png_tms, all_tms, sizeof(double));
				successful_png_tms++;
				all_tms++;
			} else {
				all_tms++;
			}

		}
		avg = averageRTT(newTimes, successful_pings, 0) / 1000;
	}

	trace->average_RTT_to_known_host = avg;

}

int createHandle(char *sniffing_device) {

	char errbuff[PCAP_ERRBUF_SIZE];

	if ((sniffing_device) == NULL) {
		fprintf(stderr, "you have not chosen a device to sniff on");
		return -1;
	}
	handle = pcap_open_live(sniffing_device, BUFSIZ, 1, -1, errbuff);

	if (handle == NULL) {
		fprintf(stderr, "could not create a handle");
		return -1;
	}
	return 1;
}

char *trace_to_string(struct timedTrace *trace) {
	char *serializedAsString = malloc(50);
	sprintf(serializedAsString, "%.2f", trace->icmp_persec);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%d",
			trace->unique_sources);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f",
			trace->tcp_syn_percentage);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f",
			trace->tcp_ack_percentage);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f",
			trace->tcp_fin_percentage);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%d",
			trace->port_errors);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%d",
			trace->ping_requests);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%d",
			trace->ping_replies);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f",
			trace->average_RTT_to_known_host);
	sprintf(&serializedAsString[strlen(serializedAsString)], "%c", ',');
	sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f",
			trace->ping_packet_loss);
	return serializedAsString;
}

void traceToFile(char *string) {
	FILE *fp;
	fp = fopen("trainingdata", "a+");
	if (fp == NULL) {
		fprintf(stderr, "could not open file for writing");
	}
	fputs(string, fp);
	fclose(fp);
}

int samplepackets(struct timedTrace *trace) {

	pthread_t pingThread;
	int threadVal;
	const unsigned char *packet;
	double record_time = 5.00, duration;
	time_t start_time;
	struct pcap_pkthdr header;

	if (rootNode != NULL) {
		rootNode = NULL;
	}
	struct PingArgs args;

	args.sourceAddress = goodSource;
	args.trace = trace;

	struct traceIntegers *traceInts = (struct traceIntegers*) malloc(
			sizeof(struct traceIntegers));

	bzero(traceInts, sizeof(struct traceIntegers));

	if (checkExistance("192.168.0.161") == 0) {
		addNode("192.168.0.161");
		traceInts->source_count++;
	}

	threadVal = pthread_create(&pingThread, NULL, getPingStats, (void *)&args);

	if (threadVal != 0){
		fprintf(stderr, "could not create a new ping thread");
	}

	start_time = time(0);

	while ((duration = difftime(time(0), start_time)) <= record_time) {

		traceInts->ping_req_count = 5;

		packet = pcap_next(handle, &header);

		if (packet != NULL) {
			inspect_pkt(packet, traceInts);
		}
	}

	pthread_join(pingThread, NULL);

	trace->icmp_persec = pkt_type_per_sec(traceInts, icmp_count, record_time);
	zerocheck(traceInts, syn_count,
			trace->tcp_syn_percentage = tcp_rel_percentage(traceInts, traceInts->syn_count));
	trace->tcp_ack_percentage = zerocheck(traceInts, ack_count,
			tcp_rel_percentage(traceInts, traceInts->ack_count));
	trace->tcp_fin_percentage = zerocheck(traceInts, fin_count,
			tcp_rel_percentage(traceInts, traceInts->fin_count));
	memcpy(&trace->ping_requests, &traceInts->ping_req_count, sizeof(int));
	memcpy(&trace->ping_replies, &traceInts->ping_rep_count, sizeof(int));
	memcpy(&trace->unique_sources, &traceInts->source_count, sizeof(int));

	addressPrinter();
	return 1;
}

int inspect_pkt(const unsigned char *packet, struct traceIntegers *traceInts) {
	struct iphdr *ip = (struct iphdr*) (packet + ethersize);

	struct in_addr srcaddr;
	srcaddr.s_addr = ip->saddr;
	char *srcaddress = strdup(inet_ntoa(srcaddr));

	if (checkExistance(srcaddress) == 0) {
		addNode(srcaddress);
		traceInts->source_count++;
	}

	switch (ip->protocol) {
	case IPPROTO_TCP:
		traceInts->tcp_count++;
		struct tcphdr *tcp = (struct tcphdr*) (packet + ethersize
				+ (ip->ihl * 4));
		switch (tcp->th_flags) {
		case TH_SYN:
			traceInts->syn_count++;
			break;
		case TH_ACK:
			traceInts->ack_count++;
			break;
		case TH_FIN:
			traceInts->fin_count++;
			break;
		}
		return 1;
	case IPPROTO_UDP:
		return 1;
	case IPPROTO_ICMP:
		traceInts->icmp_count++;
		struct icmphdr *icmp = (struct icmphdr*) (packet + ethersize
				+ (ip->ihl * 4));
		if (icmp->type == ICMP_ECHO) {
			traceInts->ping_req_count++;
		} else if (icmp->type == ICMP_ECHOREPLY) {
			traceInts->ping_rep_count++;
		}

		return 1;
	}
	return 1;
}

int train(char *sniffing_device) {

	char type[50];

	int try_CreateHandle = createHandle(sniffing_device);

	if (try_CreateHandle < 0) {
		perror("something went wrong, terminating program");
		exit(1);

	} else {
		printf(
				"please select the type of threat to gather data samples for \n");
		int i = 0;
		for (i = 0; i < 7; i++) {
			printf("%s \n", types[i]);
		}
		scanf("%s", type);

		printf("OK, gathering data for a %s attack \n", type);

		struct timedTrace *trace = (struct timedTrace*) malloc(
				sizeof(struct timedTrace));
		i = 0;
		while (i < 500) {
			samplepackets(trace);
			char *concatenated = strcat(trace_to_string(trace), ", NORMAL \n");
			traceToFile(concatenated);
			memset(trace, 0, sizeof(struct timedTrace));
			printf("\r finished sample %d of 500 \n", i);
			fflush(stdout);
			i++;
		}
		free(trace);
		puts("\n");
		puts("done sampling");
	}
	return 1;
}

int test(char *sniffing_device) {

}

void displayMenu() {

	int chosen;
	char device[20];

	puts("MAIN MENU (select an option from the following):");
	puts("1: training");
	puts("2: testing");
	puts("3: exit");
	scanf("%d", &chosen);
	switch (chosen) {
	case 1:
		puts("please enter a capture device");
		scanf("%s", device);
		goodSource = "216.58.213.110";

		train(device);
		return;
	case 2:
		puts("please enter a capture device");
		scanf("%s", device);
		puts("please enter a known host to ping against for testing purposes");
		scanf("%s", goodSource);
		test(device);
		return;
	case 3:
		exit(1);
	}
}

int main(void) {
	displayMenu();
	return 0;
}

