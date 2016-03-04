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
#include <unistd.h>
#include <sys/wait.h>
#include <ctype.h>
#include "hashmap.h"

#define traceSize 9
#define ethersize 14
#define broadcast "255.255.255.255"

pthread_mutex_t lock;

struct timeval global_pktTimer;

map *storedFlows;

char *goodSource = "152.168.2.100";

char *myAddress = "152.168.2.1";

const char *types[] = { "SYN FLOOD", "UDP FLOOD", "ICMP FLOOD", "SMURF ATTACK",
		"SLOW HTTP", "LAYER 7 ATTACK", "NORMAL TRAFFIC" };
pcap_t *handle;

struct listNode {
	char value[15];
	struct listNode *next;
};

struct listNode *allAddressesHead;
struct listNode *traceableAddresses;

double average_HTTP_end;

//classification will be done in a seperate thread so that the packets can continue being sampled while the thread is running

void set_globalTimer() {
	gettimeofday(&global_pktTimer, NULL);
}

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

//int checkExistance(char *address) {
//	temp = rootNode;
//	while (temp != NULL) {
//		if (strcmp(temp->value, address) == 0) {
//			return 1;
//		}
//		temp = temp->next;
//	}
//	return 0;
//}

struct listNode *getNodebyValue(char *address) {
	struct listNode *temp = allAddressesHead;
	while (temp != NULL) {
		if (strcmp(temp->value, address) == 0) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

struct listNode *getNodebyVal2(char *address) {
	struct listNode *temp = traceableAddresses;
	while (temp != NULL) {
		if (strcmp(temp->value, address) == 0) {
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

void printFlow(struct flowInfo *flow) {
	printf("____FLOW INFO_____ \n");
	printf("%s to: %s %s \n", flow->srcAddress, flow->destAddress,
			flow->protocol);
	printf("total number of pkts: %d \n", flow->num_pkts);
//printf("total time active %.2f millliseconds \n", flow->time_active);
	printf("total time inactive %.2f seconds \n", flow->time_inactive / 1000);

	printf("Source port: %d \n", flow->sourcePort);
	printf("Destination port: %d \n", flow->destPort);
	printf("Last recieved packet time %f \n", flow->lastRecivedTime);
	printf("Number of bytes in flow: %d \n", flow->byte_count);
	printf("\n \n");

}

void addressPrinter() {
	printf("========ALL ADDRESSESS====== \n");
	struct listNode *temp = allAddressesHead;
	while (temp != NULL) {
		printf("address: %s \n", temp->value);
		temp = temp->next;
	}
	printf("========================================= \n");
}

void addNode(char *value) {
	struct listNode *temp;
	struct listNode *new = (struct listNode*) malloc(sizeof(struct listNode));
	strcpy(new->value, value);
	new->next = NULL;
	if (allAddressesHead == NULL) {
		allAddressesHead = new;
		temp = allAddressesHead;
	} else {
		temp = allAddressesHead;
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

double calculateTimeInactive(time_t *time1, time_t *time0) {
	return (double) *time1 - *time0;
}

double calculateTimeActive(time_t *time1) {
	struct timeval now;
	gettimeofday(&now, NULL);
	return (double) now.tv_usec - *time1;
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
	timeOut.tv_sec = 1;
	timeOut.tv_usec = 0;
	to.sin_addr.s_addr = inet_addr(chosenSource);
	to.sin_family = AF_INET;

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		fprintf(stderr, "could not create socket \n");
	}

	to.sin_addr.s_addr = inet_addr(chosenSource);
	to.sin_family = AF_INET;
	to.sin_port = 9001;

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
				printf("could not create socket");

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

int checkPortUsage(int portNumber, char *destAddress) {

	struct sockaddr_in targetAddr;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0) {
		perror("could not create new socket");
	}
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_port = htons(portNumber);
	targetAddr.sin_addr.s_addr = inet_addr(destAddress);

	int connectVal = connect(sockfd, (struct sockaddr *) &targetAddr,
			sizeof(targetAddr));

	if (connectVal < 0) {
		printf("port %d is closed for %s! \n", portNumber, destAddress);
		return 0;
	}

	printf("port %d is open for %s \n", portNumber, destAddress);
	return 1;
}

char *trace_to_string(struct timedTrace *trace) {
	char *serializedAsString = malloc(100 * sizeof(char));
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

int checkReachability(char *srcAddress) {
	int exists = 0;
	int sendsock, recvsock, portno, portno2, *ttl, i = 1;
	portno = 33434;
	portno2 = 33435;
	struct sockaddr_in recvaddr, sendaddr, curraddr, target;
	char *currAddr = "172.16.0.1";
	char message[512];
	char *probemessage = "hello";
	target.sin_addr.s_addr = inet_addr(srcAddress);
	target.sin_family = AF_INET;
	target.sin_port = 33436;
	ttl = &i;
	recvaddr.sin_family = AF_INET;
	recvaddr.sin_port = portno;
	recvaddr.sin_addr.s_addr = INADDR_ANY;
	sendaddr.sin_family = AF_INET;
	sendaddr.sin_port = portno2;
	sendaddr.sin_addr.s_addr = INADDR_ANY;

	while (i < 30) {

		sendsock = socket(AF_INET, SOCK_DGRAM, 0);
		recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

		if (sendsock < 0) {
			exists = 1;

			fprintf(stderr, "could not create sending socket");
		}
		if (recvsock < 0) {
			fprintf(stderr, "could not create receiving socket");
		}
		setsockopt(sendsock, IPPROTO_IP, IP_TTL, ttl, sizeof(ttl));

		struct timeval tv;

		tv.tv_sec = 1; /* 30 Secs Timeout */
		tv.tv_usec = 0;  // Not init'ing this can cause strange errors

		setsockopt(recvsock, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv,
				sizeof(struct timeval));

		int len = sizeof(curraddr);

		if (bind(recvsock, (struct sockaddr *) &recvaddr, sizeof(recvaddr))
				< 0) {
			fprintf(stderr, "could not bind");
		}
		if (sendto(sendsock, probemessage, strlen(probemessage), 0,
				(struct sockaddr*) &target, sizeof(target)) < 0) {
			puts("did not send[100] data");
		}

		char messagebuff[512] = { 0 };

		recvfrom(recvsock, messagebuff, sizeof(message), 0,
				(struct sockaddr*) &curraddr, (socklen_t*) &len);

		struct icmphdr *icmpreplyheader = (struct icmphdr*) (messagebuff + 20);

		printf("icmp response from node: %d \n", icmpreplyheader->type);

		currAddr = strdup(inet_ntoa(curraddr.sin_addr));
		//if we have reached the host we are looking for, a port unreachable message will be sent.

		if (strcmp(currAddr, srcAddress) == 0) {
			printf("successfully reached target: %s within %d hops \n",
					currAddr, i);
			return 1;
		} else if (icmpreplyheader->type == 11) {
			printf("got to address %s in %d hops \n", currAddr, i);
		}
		close(sendsock);
		close(recvsock);
		i++;

	}

	return exists;
}

int samplepackets(struct timedTrace *trace) {

	pthread_t timeGetterThread;
	pthread_t pingThread;
	pthread_mutex_t lock;

	clock_t start = clock(), diff;

	const unsigned char *packet;
	double record_time = 5.00, duration;
	time_t start_time;

	//time_t pktRecvTime;
	struct pcap_pkthdr header;

	struct timeval now;

	pthread_mutex_init(&lock, NULL);

	//pcap does not gaurentee pkts received in order, therefore use a new time value in order to calculate times between pkts

	if (allAddressesHead != NULL) {
		allAddressesHead = NULL;
	}

	struct PingArgs args;

	args.sourceAddress = goodSource;
	args.trace = trace;

	struct traceIntegers *traceInts = (struct traceIntegers*) malloc(
			sizeof(struct traceIntegers));

	bzero(traceInts, sizeof(struct traceIntegers));

//	threadVal = pthread_create(&pingThread, NULL, getPingStats, (void *) &args);
//
//	if (threadVal != 0) {
//		fprintf(stderr, "could not create a new ping thread");
//	}

	start_time = time(0);

	//(duration = difftime(time(0), start_time)) <= record_time)

	while (1) {

		diff = clock() - start;

		packet = pcap_next(handle, &header);

		double msec = diff / (CLOCKS_PER_SEC / 1000);

		if (packet != NULL) {

			printf("recv time %f seconds \n", msec / 1000);

			//printf("%ld microseconds \n", now.tv_usec - global_pktTimer.tv_usec);

			shallow_inspect_pkt(packet, traceInts, &msec);

		}

	}

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

	printf("number of port errors %d \n", traceInts->port_error_count);

	memcpy(&trace->port_errors, &traceInts->port_error_count, sizeof(int));

	puts("all addresses");
//addressPrinter(allAddressesHead);

//	puts("traced addresses");
//	addressPrinter(traceableAddresses);

//	pthread_join(pingThread, NULL);

	return 1;
}

unsigned char *parseToAscii(const unsigned char *dataSection, int len) {

	int i = 0;

	const unsigned char *currentChar;

	char hex[2] = "";

	unsigned char *messageBuff = (unsigned char*) malloc(
			strlen(dataSection) * 2);

	currentChar = dataSection;

	for (i = 0; i < len; i++) {

		sprintf(hex, "%02x", *currentChar);
		if (strcmp(hex, "0a") == 0 || strcmp(hex, "0b") == 0) {
			messageBuff[i] = '\n';
		} else {
			if (isprint(*currentChar)) {
				messageBuff[i] = *currentChar;
			} else {
				messageBuff[i] = '.';
			}

		}
		currentChar++;
	}

	printf("\n");

	return messageBuff;

}

int isHTTP(const unsigned char *asciiText) {
	char HTTP_check[4];

	int j = 0, i = 0;
	for (j = 0; j < 4; j++) {
		HTTP_check[j] = asciiText[i + j];
	}

	if (strcmp(HTTP_check, "HTTP") == 0) {
		return 1;
	}

	return 0;
}

int inspect_HTTP(const unsigned char *asciiText, int payload_len) {

	int headerfinished = 0, i = 0;

	for (i = 0; i < payload_len; i++) {

		if (asciiText[i] == '\n') {
			if (asciiText[i + 2] == '\n') {
				printf("complete header! \n");
				headerfinished = 1;
			}
		}
	}

	//associate an incomplete connection with the source address

	return headerfinished;

}

char *ipToPlaintext(char *address) {

	char *newString = malloc(strlen(address) + 1);

	strcpy(newString, address);

	int i = 0;
	for (i = 0; i < strlen(newString); i++) {
		if (newString[i] == '.') {
			memmove(&newString[i], &newString[i + 1], strlen(newString) - i);
		}

	}

	return newString;

}

//create a new entry for the hashTable. Each flow is defined by the src address

char *createKey(char *srcAddress, char *destAddress, int *srcPort,
		int *destPort, int *proto) {

	char *createdKey = (char*) malloc(50 * sizeof(char));

	memset(createdKey, 0, strlen(createdKey) + 1);

	char *srcString = ipToPlaintext(srcAddress);

	char *destString = ipToPlaintext(destAddress);

	sprintf(createdKey, "%s%s%d%d%d", srcString, destString, *srcPort,
			*destPort, *proto);

	return createdKey;
}

struct flowInfo *create_flow(char *srcAddress, char *destAddress,
		int protocolNum, int sourcePort, int destPort, double *timeStamp,
		int *byte_count) {

	struct flowInfo *newFlow = (struct flowInfo*) malloc(
			sizeof(struct flowInfo));

	newFlow->srcAddress = srcAddress;
	newFlow->destAddress = destAddress;
	switch (protocolNum) {
	case 6:
		newFlow->protocol = "TCP";
		break;
	case 17:
		newFlow->protocol = "UDP";
		break;
	case 1:
		newFlow->protocol = "ICMP";
		break;
	}

	newFlow->sourcePort = sourcePort;

	newFlow->destPort = destPort;

	newFlow->lastRecivedTime = *timeStamp;

	newFlow->byte_count = *byte_count;

	newFlow->num_pkts = 1;

	return newFlow;

}

int shallow_inspect_pkt(const unsigned char *packet,
		struct traceIntegers *traceInts, double *pktTimeStamp) {

	struct timeval recvTime;

	gettimeofday(&recvTime, NULL);

	struct iphdr *ip = (struct iphdr*) (packet + ethersize);

	const unsigned char *payload;
	const unsigned char *payloadAsAscii;

	int sport_num, dport_num, totalsize, protocolnum;

	struct in_addr srcaddr, destaddr;
	srcaddr.s_addr = ip->saddr;
	destaddr.s_addr = ip->daddr;

	totalsize = (int) ip->tot_len;

	printf("total packet size %d \n", totalsize);

	char *srcaddress = strdup(inet_ntoa(srcaddr));
	char *destaddress = strdup(inet_ntoa(destaddr));

	struct listNode *addressNode = getNodebyValue(srcaddress);

	if (addressNode == NULL) {
		addNode(srcaddress);
		traceInts->source_count++;
	}

	int ip_size = ip->ihl * 4;

//method below needs fixing.

//	int isTraceable = checkReachability(srcaddress);
//	if (isTraceable < 1) {
//		printf("found no route to this %s address \n", srcaddress);
//	}

	protocolnum = (int) ip->protocol;

	switch (ip->protocol) {
	case IPPROTO_TCP:
		traceInts->tcp_count++;

		struct tcphdr *tcp = (struct tcphdr*) (packet + ethersize + ip_size);

		int tcp_size = tcp->doff * 4;

		int payload_size = ntohs(ip->ihl - (ip_size - tcp_size));

		sport_num = ntohs(tcp->th_sport);

		dport_num = ntohs(tcp->th_dport);

		if (payload_size > 0) {

			payload =
					(unsigned char*) (packet + ethersize + ip_size + tcp_size);

			//payloadAsAscii = parseToAscii(payload, payload_size);

//			if ((sport_num == 80 || dport_num == 80)) {
//				if (isHTTP(payloadAsAscii)) {
//					printf("%s \n", payloadAsAscii);
//				}
//
//			}
		}
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
		break;

	case IPPROTO_UDP:
		;
		;
		struct udphdr *udp = (struct udphdr*) (packet + ethersize
				+ (ip->ihl * 4));

		sport_num = ntohs(udp->uh_sport);
		dport_num = ntohs(udp->uh_dport);

		break;
	case IPPROTO_ICMP:
		traceInts->icmp_count++;
		struct icmphdr *icmp = (struct icmphdr*) (packet + ethersize
				+ (ip->ihl * 4));
		switch (icmp->type) {
		case ICMP_ECHO:
			traceInts->ping_req_count++;
			break;
		case ICMP_ECHOREPLY:
			traceInts->ping_rep_count++;
			break;
		case ICMP_DEST_UNREACH:
			if (icmp->code == 3) {
				puts("unreachable port error detected");
				traceInts->port_error_count++;
			}
			break;
		}
		break;
	}

	char *key = createKey(srcaddress, destaddress, &sport_num, &dport_num,
			&protocolnum);

	int entryPlace = hashmap_get_hash(key, storedFlows->size);

	printf("%d \n", entryPlace);

	entry *entry = storedFlows->table[entryPlace];

	if (entry == NULL) {
		puts("no existing entry");
		//printf("pkt time :%f \n", (double) *pktTimeStamp);

		struct flowInfo *newFlow = create_flow(srcaddress, destaddress,
				ip->protocol, sport_num, dport_num, pktTimeStamp, &totalsize);

		puts("created new flow");

		assert(newFlow != NULL);
		hashmap_insert_entry(key, newFlow, storedFlows);

		//printFlow(newFlow);
	}

	else {

		//double activeTime = calculateTimeActive(pktTimeStamp);

		struct flowInfo *entryData = (struct flowInfo*) entry->data;
		entryData->byte_count += totalsize;
		entryData->num_pkts += 1;
		entryData->time_inactive += *pktTimeStamp - entryData->lastRecivedTime;
		entryData->lastRecivedTime = *pktTimeStamp;

		printFlow(entry->data);

		//entryData->time_active += activeTime;

	}

	//entry *entry = hashmap_get_entry_by_key(key, storedFlows);

	return 1;
}

int train(char *sniffing_device) {

	char type[50];
	int samplesize;

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

		printf("please enter the number of samples to be collected:");

		scanf("%d", &samplesize);

		printf("OK, gathering %d samples for %s traffic \n", samplesize, type);

		struct timedTrace *trace = (struct timedTrace*) malloc(
				sizeof(struct timedTrace));
		i = 0;
		while (i < samplesize) {
			memset(trace, 0, sizeof(struct timedTrace));
			samplepackets(trace);
			char *trace_as_string = trace_to_string(trace);
			char *str1 = strcat(trace_as_string, " ");
			char *str2 = strcat(str1, type);
			char *final = strcat(str2, "\n");
			traceToFile(final);
			printf("\r finished sample %d of %d \n", i + 1, samplesize);
			fflush(stdout);
			i++;
		}
		free(trace);
		puts("\n");
		puts("done sampling");
	}
	return 1;
}

void *classificationTread(void *arg) {
	int inputPipe[2], outputPipe[2], status;
	char readBuffer[80];
	pid_t waitPID, childPID;

	struct timedTrace *trace = (struct timedTrace*) arg;

	char *args = strcat(trace_to_string(trace), "\n");

	status = 0;

	pipe(inputPipe);
	pipe(outputPipe);

	childPID = fork();

	if (childPID == -1) {
		perror("error creating child process");
	}

//if we are the child process
	if (childPID == 0) {
		puts("running classifier...");
		close(inputPipe[1]);
		close(outputPipe[0]);
		dup2(inputPipe[2], STDIN_FILENO);
		dup2(outputPipe[1], STDOUT_FILENO);
		char *pythonArgs[] = { "python", "./volumebasedclassifier.py",
		NULL };
		execvp("python", pythonArgs);
		exit(0);
	} else {
		close(inputPipe[0]);
		close(outputPipe[1]);
		write(inputPipe[1], args, 6);
		waitPID = wait(&status);
		printf(" \n parent detected child process %d is done \n", waitPID);
		read(outputPipe[0], readBuffer, sizeof(readBuffer));
		printf("outputted class: %s \n", readBuffer);

	}
}

void classifier(struct timedTrace *trace) {
	fflush(stdout);
	fflush(stdin);

	int inputPipe[2], outputPipe[2], status;
	char readBuffer[80];
	pid_t waitPID, childPID;

	char *args = strcat(trace_to_string(trace), "\n");

	printf("%s \n", args);

	status = 0;

	pipe(inputPipe);
	pipe(outputPipe);

	childPID = fork();

	if (childPID == -1) {
		perror("error creating child process");
	}
//if we are the child process
	if (childPID == 0) {

		puts("Determining type...");
		close(inputPipe[1]);
		close(outputPipe[0]);
		dup2(inputPipe[0], STDIN_FILENO);
		dup2(outputPipe[1], STDOUT_FILENO);
		char *pythonArgs[] = { "python", "./volumebasedclassifier.py",
		NULL };
		execvp("python", pythonArgs);
		exit(0);
	} else {
		close(inputPipe[0]);
		close(outputPipe[1]);
		write(inputPipe[1], args, strlen(args));
		waitPID = wait(&status);
		printf(" \n parent detected child process %d is done \n", waitPID);
		read(outputPipe[0], readBuffer, sizeof(readBuffer));
		printf("outputted class: %s \n", readBuffer);

	}
}

int test(char *sniffing_device) {

	if (createHandle(sniffing_device) < 0) {
		perror("could not create handle");
	}

	struct timedTrace *trace = (struct timedTrace*) malloc(
			sizeof(struct timedTrace));

	puts("monitoring network traffic...");

	set_globalTimer();

	while (1) {
		//pthread_t analyzerthread;
		memset(trace, 0, sizeof(struct timedTrace));
		samplepackets(trace);
		classifier(trace);
		//pthread_create(&analyzerthread, NULL, classificationTread, trace);
		//pthread_join(analyzerthread, NULL);

	}

	fprintf(stderr, "monitoring stopped!");
	free(trace);
	return 0;
}

int testKeyCreation() {
	char *expected_output1 = "19216856101256781012028064531";
	char *srcAddress = "192.168.56.101";
	char *destAddres = "256.78.101.202";
	int proto = 1;
	int s_portNum = 80;
	int d_portNum = 6453;
	assert(
			strcmp(
					createKey(srcAddress, destAddres, &s_portNum, &d_portNum,
							&proto), expected_output1) == 0);
	return 0;

}

int Insert_check(map *hmap) {

	char *key1 = "124356794354930545430824498394347432077373743242";
	char *data1 = "newData";

	assert(hmap->size > 0);
	int hash = hashmap_get_hash(key1, hmap->size);
	printf("hash = %d \n", hash);
	assert(hashmap_insert_entry(key1, data1, hmap) == 0);

	assert(hashmap_get_entry_by_key(key1, hmap) != NULL);

	puts("insertion check ok!");

	return 0;
}

int runTestEvents() {
	testKeyCreation();
	puts("created test key OK!");
	map *newMap = hashmap_createMap(500);
	puts("created a new hashmap OK!");
	Insert_check(newMap);
	puts("hashmap functionality ok!");
	free(newMap);
	return 0;
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
		train(device);
		return;
	case 2:

		puts("please enter a capture device");
		scanf("%s", device);
		test(device);
		return;
	case 3:
		exit(1);
	}
}

int main() {
	storedFlows = hashmap_createMap(1000);
	assert(storedFlows !=NULL);
	//runTestEvents();
	//printf("done testing \n");
	displayMenu();
	free(storedFlows);
	return 0;
}


