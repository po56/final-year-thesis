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
#include <sys/un.h>
#include <ctype.h>
#include "hashmap.h"
#include <regex.h>
#include <net/ethernet.h>
#include "linkedList.h"


#define ethersize 14
#define MAXPKTSIZE 65535

regex_t sql_oneequalsone;

struct timeval sample_start_time;

map *storedFlows;
map *HTTPCache;

//allow the maximum amount
unsigned char requestbuffer[BUFSIZ * 3];

char *goodSource = "152.168.2.100";
char *myAddress = "152.168.2.1";
int trainingenabled, alertHasBeenRaised, totalHTTPconnections = 0;
struct traceIntegers *traceInts;

pcap_t *handle;

struct listNode {
    char value[15];
    struct listNode *next;
};

struct listNode *allAddressesHead;
struct listNode *traceableAddresses;
double average_HTTP_end;

clock_t samplestarttime;


//in case our administrator is not logged into the system at the time

void sendSMTP(char *message) {

}

//uses the wall command to broadcast to all users

void broadcast_alert(char *dir) {
    char commandBuff[BUFSIZ];
    sprintf(commandBuff, "%s", "wall <");
    sprintf(commandBuff + strlen(commandBuff), "%s", dir);
    printf("%s", commandBuff);
    system(commandBuff);
}

void createDialog(char *dir){
    char commandBuff[BUFSIZ];
    sprintf(commandBuff, "%s", "dialog --title 'INTRUSION DETECTED' --textbox ");
    sprintf(commandBuff + strlen(commandBuff), "%s 500 2000", dir);
    system(commandBuff);
}

void createAlert(char *type, struct timeval *detectedTime, listnode *suspectFlows) {

    struct tm *timeinfo;
    char alertMessage[BUFSIZ];
    char timeBuffer[100];
    timeinfo = localtime(&detectedTime->tv_sec);
    strftime(timeBuffer, 100, "%c", timeinfo);
    printf("time %s \n", timeBuffer);
    sprintf(alertMessage, "%s", "ALERT, A THREAT HAS BEEN DETECTED! \n");
    sprintf(alertMessage + strlen(alertMessage), "Time Detected: %s \t Threat Type %s \n", timeBuffer, type);
    sprintf(alertMessage + strlen(alertMessage), "Affected Hosts: \n");

    listnode *temp = suspectFlows;

    if(strcmp(type, "SQLi") == 0){
        struct SQLi *sqlidata = (struct SQLi*)temp->data;
        sprintf(alertMessage + strlen(alertMessage), "%s \n", sqlidata->dst);
        sprintf(alertMessage + strlen(alertMessage), "suspect source address : %s \n", sqlidata->src);
        sprintf(alertMessage + strlen(alertMessage), "suspect data: %s \n", sqlidata->str);
        FILE *tmpsqlalertfile;
        tmpsqlalertfile = fopen("sqltmp.txt", "w");
        fputs(alertMessage, tmpsqlalertfile);
        fclose(tmpsqlalertfile);
        broadcast_alert("sqltmp.txt");
        createDialog("sqltmp.txt");


    }else {

        while (temp != NULL) {
            struct flowInfo *flowData = (struct flowInfo *) temp->data;
            sprintf(alertMessage + strlen(alertMessage), "%s", flowData->destAddress);
            sprintf(alertMessage + strlen(alertMessage), "%c", '\n');
            temp = temp->next;
        }

        //since the wall command only allows up to 20 lines, we simply give the key information and not info about the suspected addresses

        FILE *tempFile;
        tempFile = fopen("tmpmsgfile.txt", "w");

        assert(tempFile != NULL);
        fputs(alertMessage, tempFile);
        fclose(tempFile);

        broadcast_alert("tmpmsgfile.txt");

        sprintf(alertMessage + strlen(alertMessage), "%s", "SUSPECT FLOWS \n");

        temp = suspectFlows;

        if (strcmp(type, "SQLi") == 0)

            while (temp != NULL) {
                struct flowInfo *flowData = (struct flowInfo *) temp->data;
                sprintf(alertMessage + strlen(alertMessage), "%s -> %s %s \n", flowData->srcAddress,
                        flowData->destAddress, flowData->protocol);
                sprintf(alertMessage + strlen(alertMessage), "ports %d -> %d \n", flowData->sourcePort,
                        flowData->destPort);
                sprintf(alertMessage + strlen(alertMessage), "%d packets %d bytes \n", flowData->num_pkts,
                        flowData->byte_count);
                temp = temp->next;
            }

        puts(alertMessage);

        tempFile = fopen("tmpmsgfile.txt", "w");
        fputs(alertMessage, tempFile);
        fclose(tempFile);

        createDialog("tmpmsgfile.txt");

    }

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


void addressPrinter() {
    printf("========ALL ADDRESSESS====== \n");
    struct listNode *temp = allAddressesHead;
    while (temp != NULL) {
        printf("address: %s \n", temp->value);
        temp = temp->next;
    }
    printf("============================= \n");
}

void addNode(char *value) {
    struct listNode *temp;
    struct listNode *new = (struct listNode *) malloc(sizeof(struct listNode));
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


void sendEchoRequest(struct sockaddr_in *target, int sockfd, char *data) {
    int ID = getpid() & 0xFFFF;

    unsigned char *sentpacket;

    struct icmphdr icp;

    icp.code = 0;
    icp.type = ICMP_ECHO;
    icp.un.echo.id = ID;
    icp.checksum = 0;
    icp.un.echo.sequence = 0;

    sentpacket = (unsigned char *) malloc(IP_MAXPACKET * sizeof(unsigned char));

    memcpy(sentpacket, &icp, 8);
    //and also the icmp data
    memcpy(sentpacket + 8, data, strlen(data));
    //calculate the checksum
    icp.checksum = in_cksum((unsigned short *) sentpacket, 8 + strlen(data));
    //and update the packet
    memcpy(sentpacket, &icp, 8);

    if (sendto(sockfd, sentpacket, 8 + strlen(data), 0,
               (struct sockaddr *) target, sizeof(*target)) < 0) {
        perror("could not send");
    }

}

void *getPingStats(void *args) {
#define loss(X, Y)(X/Y)

    char *data = "testping";

    struct PingArgs *arguments = args;

    char *chosenSource = arguments->sourceAddress;

    struct timedTrace *trace = arguments->trace;

    unsigned char *sentpacket, *recievedpacket;
    double avg;
    struct timeval sndTime, recvTime, timeOut;
    struct sockaddr_in to;
    int n_transmitted = 0, n_to_transmit = 5, nLost = 0,
            sockfd, successful_pings;
    double times[5] = {0};
    timeOut.tv_sec = 1;
    timeOut.tv_usec = 0;

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        fprintf(stderr, "could not create socket \n");
    }

    to.sin_addr.s_addr = inet_addr(chosenSource);
    to.sin_family = AF_INET;
    to.sin_port = 9001;

    memset(&to.sin_zero, 0, sizeof(to.sin_zero));

    recievedpacket = (unsigned char *) malloc(IP_MAXPACKET);

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeOut,
                   sizeof(timeOut)) < 0) {
        fprintf(stderr, "could not set timeout option \n");
    }

    while (n_transmitted < n_to_transmit) {
        sendEchoRequest(&to, sockfd, data);

        gettimeofday(&sndTime, NULL);

        if (recvfrom(sockfd, recievedpacket,
                     sizeof(struct icmphdr) + strlen(data), 0, NULL,
                     (socklen_t *) sizeof(struct sockaddr)) >= 0) {
            gettimeofday(&recvTime, NULL);
            struct iphdr *recievedip = (struct iphdr *) (recievedpacket);
            struct icmphdr *receivedicmp = (struct icmphdr *) (recievedpacket
                                                               + (recievedip->ihl * 4));

            if (receivedicmp->type == ICMP_ECHOREPLY) {
                double timeTaken = (recvTime.tv_usec - sndTime.tv_usec);
                times[n_transmitted] = timeTaken;
                //this works on mininet as the controller becomes so overwhelemed it cannot find a suitable route to the host
            } else if (receivedicmp->type == ICMP_UNREACH) {
                nLost++;
            }

        } else {
            //if there was no data recieved from the source, implies the request timed out.
            perror("something went wrong when trying to receive: ");
            nLost++;
        }

        n_transmitted++;
    }

    trace->ping_packet_loss = loss((double) nLost, (double) n_transmitted);

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

    handle = pcap_create(sniffing_device, errbuff);

    pcap_set_tstamp_type(handle, PCAP_TSTAMP_ADAPTER);

    //maximum frame size + 1 for null terminating char.

    pcap_set_snaplen(handle, 65536);

    pcap_activate(handle);

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
    sprintf(serializedAsString, "%.2f,", trace->icmp_persec);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%d,",
            trace->unique_sources);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f,",
            trace->tcp_syn_percentage);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f,",
            trace->tcp_ack_percentage);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%d,",
            trace->port_errors);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%d,",
            trace->ping_requests);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%d,",
            trace->ping_replies);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f,",
            trace->average_RTT_to_known_host);
    sprintf(&serializedAsString[strlen(serializedAsString)], "%.2f,",
            trace->ping_packet_loss);
    return serializedAsString;
}

void traceToFile(char *string, char *trainingdata_filename) {
    FILE *fp;
    fp = fopen(trainingdata_filename, "a+");
    if (fp == NULL) {
        fprintf(stderr, "could not open file for writing");
    }
    fputs(string, fp);
    fclose(fp);
}

int checkReachability(char *srcAddress) {
    int exists = 0;
    int sendsock, recvsock, portno, *ttl, i = 1;
    portno = 33434;
    struct sockaddr_in recvaddr, curraddr, target;
    char *currAddr;
    char message[512];
    char *probemessage = "hello";
    target.sin_addr.s_addr = inet_addr(srcAddress);
    target.sin_family = AF_INET;
    target.sin_port = 33435;
    recvaddr.sin_family = AF_INET;
    recvaddr.sin_port = portno;
    recvaddr.sin_addr.s_addr = INADDR_ANY;

    struct timeval timeout;

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    //30 hops should be more than enough to reach our target destination
    while (i < 30) {
        ttl = &i;
        sendsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        assert(sendsock > 0);
        assert(recvsock > 0);
        //set the time to live
        setsockopt(sendsock, IPPROTO_IP, IP_TTL, ttl, sizeof(ttl));

        setsockopt(recvsock, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout,
                   sizeof(struct timeval));
        int len = sizeof(curraddr);
        assert(bind(recvsock, (struct sockaddr *) &recvaddr, sizeof(recvaddr))
               >= 0);
        sendEchoRequest(&target, sendsock, probemessage);

        char messagebuff[512] = {0};
        recvfrom(recvsock, messagebuff, sizeof(message), 0,
                 (struct sockaddr *) &curraddr, (socklen_t *) &len);

        struct icmphdr *icmpreplyheader = (struct icmphdr *) (messagebuff + 20);

        printf("icmp response from node: %d \n", icmpreplyheader->type);

        currAddr = strdup(inet_ntoa(curraddr.sin_addr));

        if (strcmp(currAddr, srcAddress) == 0) {
            printf("successfully reached target: %s within %d hops \n",
                   currAddr, i);
            return 1;
        } else if (icmpreplyheader->type == 11) {
            printf("got to address %s in %d hops \n", currAddr, i);
            if (sendto(sendsock, probemessage, strlen(probemessage), 0,
                       (struct sockaddr *) &target, sizeof(target)) < 0) {
                puts("did not send[100] data");
            }
        }
        close(sendsock);
        close(recvsock);
        i++;

    }

    return exists;
}


void handlePacket(struct pcap_pkthdr *header,
                  const unsigned char *packet) {

    long int seconds = header->ts.tv_sec - sample_start_time.tv_sec;
    long int microseconds = header->ts.tv_usec - sample_start_time.tv_usec;
    double microsecondsasdouble = seconds * 1000000.0 + microseconds;
    double secondsasdouble = microsecondsasdouble / 1000000;

    shallow_inspect_pkt(packet, traceInts, &secondsasdouble, header->len);

}

int samplepackets(struct timedTrace *trace) {
    puts("starting new sample");
    pthread_t pingThread;
    double record_time = 5.00, duration;\
    time_t start_time;
    struct pcap_pkthdr header;

    if (allAddressesHead != NULL) {
        allAddressesHead = NULL;
    }

    struct PingArgs args;

    args.sourceAddress = goodSource;
    args.trace = trace;

    traceInts = (struct traceIntegers *) malloc(sizeof(struct traceIntegers));

    bzero(traceInts, sizeof(struct traceIntegers));

    int threadVal = pthread_create(&pingThread, NULL, getPingStats, (void *) &args);

    if (threadVal != 0) {
        fprintf(stderr, "could not create a new ping thread");
    }

    start_time = time(0);

    while (difftime(time(0), start_time) <= record_time) {
        const unsigned char *packet = pcap_next(handle, &header);
        if (packet != NULL) {
            handlePacket(&header, packet);
        }
    }

    trace->icmp_persec = pkt_type_per_sec(traceInts, icmp_count, record_time);

    printf("tcp count %f", traceInts->tcp_count);

    if (traceInts->tcp_count > 0){
        trace->tcp_syn_percentage = traceInts->syn_count/ traceInts->tcp_count;
        trace->tcp_ack_percentage = traceInts->ack_count/traceInts->tcp_count;
    }


    memcpy(&trace->ping_requests, &traceInts->ping_req_count, sizeof(int));
    memcpy(&trace->ping_replies, &traceInts->ping_rep_count, sizeof(int));
    memcpy(&trace->unique_sources, &traceInts->source_count, sizeof(int));
    memcpy(&trace->port_errors, &traceInts->port_error_count, sizeof(int));

    return 1;
}

int is_truncated(char *HTTPPacket) {
    int truncated = 1;

    if (strstr(HTTPPacket, "\r\n\r\n") != NULL) {
        truncated = 0;
    }

    return truncated;

}

unsigned char *parseToAscii(const unsigned char *dataSection, int len) {

    int i = 0;
    const unsigned char *currentChar;
    char hex[4];
    unsigned char *messageBuff = (unsigned char *) malloc((len + 1) * sizeof(char));
    currentChar = dataSection;
    for (i = 0; i < len; i++) {
        sprintf(hex, "%02x", *currentChar);
        if (strcmp(hex, "0a") == 0) {
            messageBuff[i] = '\n';
        } else {
            if (strcmp(hex, "0d") == 0) {
                messageBuff[i] = '\r';
            } else {
                if (isprint(*currentChar)) {
                    messageBuff[i] = *currentChar;
                } else {
                    messageBuff[i] = '.';
                }
            }
        }
        currentChar = currentChar + 1;
    }
    return messageBuff;

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

    char *createdKey = (char *) malloc(50 * sizeof(char));

    memset(createdKey, 0, strlen(createdKey) + 1);

    char *srcString = ipToPlaintext(srcAddress);

    char *destString = ipToPlaintext(destAddress);

    sprintf(createdKey, "%s%s%d%d%d", srcString, destString, *srcPort,
            *destPort, *proto);

    return createdKey;
}

char *createHTTPCacheKey(char *srcAddress, char *destAddress, int *srcPort) {

    char *createdKey = (char *) malloc(50 * sizeof(char));

    memset(createdKey, 0, strlen(createdKey) + 1);

    char *srcString = ipToPlaintext(srcAddress);

    char *destString = ipToPlaintext(destAddress);

    sprintf(createdKey, "%s%s%d", srcString, destString, *srcPort);

    return createdKey;
}

struct HTTPCacheEntry *createHTTPCacheEntry(char *srcaddr, char *destaddr,
                                            int *srcport, const char *data) {
    struct HTTPCacheEntry *newCacheEntry = (struct HTTPCacheEntry *) malloc(
            sizeof(struct HTTPCacheEntry));
    newCacheEntry->destAddress = destaddr;
    newCacheEntry->srcAddress = srcaddr;
    newCacheEntry->sourcePort = srcport;
    newCacheEntry->truncated_data = data;
    return newCacheEntry;
}

struct flowInfo *create_flow(char *srcAddress, char *destAddress,
                             int protocolNum, int sourcePort, int destPort, double *timeStamp,
                             int *byte_count, int unreachable, int SYN, int ACK) {


    struct flowInfo *newFlow = (struct flowInfo *) malloc(
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

    newFlow->tcpSYNSTransmiteed = SYN;

    newFlow->tcpACKSTransmitted = ACK;

    newFlow->unreachableErrorsInvoked = unreachable;

    return newFlow;

}

listnode get_suspects(char *type) {

    listnode *suspect_addresses = (listnode*)malloc(sizeof(listnode));

    char *cond = malloc(100 * sizeof(char));

    if (strcmp(type, "SYNFLOOD") == 0) {

        int i = 0;
        for (i = 0; i < storedFlows->size; i++) {
            entry *entry = storedFlows->table[i];
            struct flowInfo *entryData = (struct flowInfo *) entry->data;
            if (strcmp(entryData->protocol, "TCP") == 0 &&
                entryData->tcpSYNSTransmiteed > entryData->tcpACKSTransmitted) {
                linkedList_add(suspect_addresses, entryData);
            }
        }

    } else if (strcmp(type, "UDPFLOOD") == 0) {
        int i = 0;
        for (i = 0; i < storedFlows->size; i++) {
            entry *entry = storedFlows->table[i];
            struct flowInfo *entryData = (struct flowInfo *) entry->data;
            //print all of the addresses that have produced unreachable port errors. This may produce some false positives.
            if (strcmp(entryData->protocol, "UDP") == 0 && entryData->unreachableErrorsInvoked > 0) {
                linkedList_add(suspect_addresses, entryData);
                //Another condition here specifying that the last recieved time must be between the sample start time and the time deteced.
            }

        }

    } else if (strcmp(type, "ICMPFLOOD") == 0) {
        int i = 0;
        for (i = 0; i < storedFlows->size; i++) {
            entry *entry = storedFlows->table[i];
            struct flowInfo *entryData = (struct flowInfo *) entry->data;
            //print all of the addresses that have produced unreachable port errors. This may produce some false positives.
            if (strcmp(entryData->protocol, "UDP") == 0 && entryData->unreachableErrorsInvoked > 0) {
                linkedList_add(suspect_addresses, entryData);
                //Another condition here specifying that the last recieved time must be between the sample start time and the time deteced.
            }
        }

    } else if (strcmp(type, "SMURFLOOD") == 0) {

    }
}

void classifydata(char *data, char *serverDomain, char *type) {

    clock_t detectedTime;
//THIS app acts as the client, where the server is the python program for classification.
//UNIX DOMAIN SOCKET KNOWN BY A PATHNAME
    /*
     * SOCKETS vs PIPEs
     * sockets provide bi directional communication, named pipes are uni directional. Therefore, we only need one socket for what we could do with 2 pipes
     * Clients using the socket each have an independent conneciton to the server
     */

    //next optimisation: make this multithreaded so that we can classify whilst we are still collecting data
    int sock, len;
    struct sockaddr_un remote;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock < 0) {
        perror("could not create socket");
        exit(-1);
    }

    memset(&remote, 0, sizeof(struct sockaddr_un));

    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, serverDomain);

    len = sizeof(remote.sun_family) + strlen(remote.sun_path);

    int connected = connect(sock, (struct sockaddr *) &remote, len);

    if (connected == -1) {
        perror("could not connect");
        exit(-1);
    }
    if (send(sock, data, strlen(data), 0) < 0) {
        perror("error sending data to classifier");
        exit(-1);
    }

    char messagebuff[4];

    read(sock, messagebuff, 4);


    close(sock);

}

int packet_fragmentation_check(struct ip *hdr, int len) {
    int result = 0;
    //initial check, make sure that the packet itself is not bigger than the
    if (len > MAXPKTSIZE) {
        result = 1;
    } else {
        if (hdr->ip_off + hdr->ip_len > MAXPKTSIZE) {
            result = 1;
        } else {
            short fragmentflags = hdr->ip_off & IP_OFFMASK;
            if (fragmentflags & IP_MF) {
                if (len == MAXPKTSIZE) {
                    result = 1;
                }

            }
        }
    }
    return result;

}

int isHTTP(const unsigned char *packetdata) {


#define HTTP "HTTP/1.1"

    int res = 0;

    int len = strlen((char *) packetdata);

    unsigned char *headerline = (unsigned char *) malloc((len + 1) * sizeof(char));

    strcpy(headerline, (unsigned char *) packetdata);

    char *line = strchr(headerline, '\r');

    if (line) {
        *line = '\0';
        unsigned char *HTTPCheck = headerline + strlen(headerline) - strlen(HTTP);

        if (strcmp(HTTPCheck, HTTP) == 0) {
            *line = '\r';
            res = 1;
        }

    }

    return res;

}

void compileSQLRegex() {

    char *sqlexpressions = "[[:blank:]]+(and|or|OR|AND)[[:blank:]]+[-\\+]?[[:blank:]]*[[:digit:]\\.]+[[:blank:]]*[<>=!]{1,2}[[:blank:]]*[-\\+]?[[:blank:]]*[[:digit:]\\.]+";

    int compiled = regcomp(&sql_oneequalsone, sqlexpressions, REG_EXTENDED);

    if (compiled != 0) {
        fprintf(stderr, "could not compile sql regex, terminating program");
        exit(-1);
    }

}

void parseSQL(char *requestdata, char *source, char *dest) {
    struct timeval detectionTime;

    regex_t *regexptr = &sql_oneequalsone;

    int match = regexec(regexptr, requestdata, 0, NULL, 0);

    if (match == 0) {
        gettimeofday(&detectionTime, NULL);
        struct SQLi *sqlnodedata = (struct SQLi*)malloc(sizeof(struct SQLi));
        sqlnodedata->src = source;
        sqlnodedata->str = requestdata;
        sqlnodedata->dst = dest;
        listnode *SQLiNode = linkedList_add(NULL, sqlnodedata);
        createAlert("SQLi", &detectionTime, SQLiNode);
    }

}

void inspectHTTPData(const char *HTTPacket, int payload_len, char *source, char *dest) {
    char *datacopy = (char *) malloc((payload_len + 1) * sizeof(char));
    strcpy(datacopy, HTTPacket);
    char *requestmethodboundary = strstr(datacopy, " ");
    *requestmethodboundary = '\0';

    //Process POST requests for SQLi Attack
    if (strcmp(datacopy, "POST") == 0) {
        puts("PARSING HTTP POST");
        *requestmethodboundary = ' ';
        char *contentLength = strstr(datacopy, "Content-Length") + strlen("Content-Length: ");
        char *contentLengthEnd = strstr(contentLength, "\r\n");
        *contentLengthEnd = '\0';
        int con_len = atoi(contentLength);
        *contentLengthEnd = '\r';

        char *data_start = strstr(datacopy, "\r\n\r\n") + 4;
        char *data_end = data_start + con_len;

        *data_end = '\0';
        char *encoded_data = malloc((con_len + 1) * sizeof(char));
        strcpy(encoded_data, data_start);
        parseSQL(encoded_data, source, dest);

    } else if (strcmp(datacopy, "GET") == 0) {
        *requestmethodboundary = ' ';
    }
}


int shallow_inspect_pkt(const unsigned char *packet,
                        struct traceIntegers *traceInts, double *pktTimeStamp, int totalPktSize) {

    int payload_size;
    int isACK;
    int isSYN;
    int isUnreachable;

    struct ethhdr *eth = (struct ethhdr *) packet;
    struct ip *ip = (struct ip *) (packet + ethersize);

    const unsigned char *payload;
    const unsigned char *payloadAsAscii;


    int sport_num, dport_num, totalsize, protocolnum, isconnecting;

    struct in_addr srcaddr, destaddr;

    srcaddr.s_addr = ip->ip_src.s_addr;
    destaddr.s_addr = ip->ip_dst.s_addr;

    totalsize = (int) ip->ip_len;

    //if (packet_fragmentation_check(ip, totalPktSize)) {
    //    
    //}

    char *srcaddress = strdup(inet_ntoa(srcaddr));
    char *destaddress = strdup(inet_ntoa(destaddr));

    struct listNode *addressNode = getNodebyValue(srcaddress);
    if (addressNode == NULL) {
        addNode(srcaddress);
        traceInts->source_count++;
    }

    int ip_size = ip->ip_hl * 4;

    protocolnum = (int) ip->ip_p;

    switch (protocolnum) {
        case IPPROTO_TCP:
            traceInts->tcp_count++;
            struct tcphdr *tcp = (struct tcphdr *) (packet + ethersize + ip_size);

            int header_length = sizeof(struct ethhdr) + ip_size + tcp->doff * 4;

            sport_num = ntohs(tcp->th_sport);

            dport_num = ntohs(tcp->th_dport);

            int tcpsequencenum = ntohs(tcp->seq);


            if (dport_num == 80) {

                totalHTTPconnections += isconnecting;

                int fragmented = (ip->ip_off & IP_OFFMASK) & IP_MF;
                if (fragmented) {
                    puts("fragmented datagram");
                } else {

                    /* REASSEMBLY OF THE HTTP STREAM USING A CACHE HASHMAP
                         * stores the current body of the request in the map along with the sequence number
                         * this is later accessed by the next set of packets
                         */


                    payloadAsAscii = parseToAscii(packet + header_length, totalPktSize - header_length);

                    if ((tcp->th_flags & TH_PUSH) && (tcp->th_flags & TH_ACK)) {

                        char *key = createHTTPCacheKey(srcaddress, destaddress,
                                                       &sport_num);

                        int HTTPCacheAddr = hashmap_get_hash(key, HTTPCache->size);

                        entry *cached_data_entry = HTTPCache->table[HTTPCacheAddr];

                        if (cached_data_entry != NULL) {

                            struct HTTPCacheEntry *cached_data_data =
                                    (struct HTTPCacheEntry *) cached_data_entry->data;

                            if (tcpsequencenum == *cached_data_data->lastseqnum) {

                                int newlength = strlen((char *) cached_data_data->truncated_data) +
                                                strlen((char *) payloadAsAscii) + 1;

                                char *newpayload = (char *) malloc(newlength * sizeof(char));

                                sprintf(newpayload, "%s",
                                        cached_data_data->truncated_data);
                                int previousdatalen = strlen(cached_data_data->truncated_data);

                                sprintf(
                                        newpayload
                                        + previousdatalen,

                                        "%s", payloadAsAscii);

                                unsigned char *newpayload_asciival = parseToAscii(
                                        (unsigned char *) newpayload,
                                        strlen(newpayload));

                                if (is_truncated((char *) newpayload_asciival) == 1) {
                                    cached_data_data->truncated_data =
                                            (char *) newpayload_asciival;
                                    printf("Modified HTTP payload: \n %s \n",
                                           cached_data_data->truncated_data);
                                } else {
                                    printf("Reconstructed HTTP payload: \n %s \n",
                                           newpayload_asciival);
                                    HTTPCache->table[HTTPCacheAddr] = NULL;
                                }

                            }

                        } else {

                            /*
                            * perform this check in the case that we pick up a TCP retransmission/ part of a request that is NOT part of a whole header.
                            * note, we are only concerned here with the requests, not the responses, as we are looking for malicious REQUESTS and assuming that our servers generate legitimate/ safe replies.
                            */

                            if (isHTTP(payloadAsAscii)) {
                                //check for CLRF followed by CLRF, terminating the request
                                if (is_truncated((char *) payloadAsAscii) == 1) {

                                    printf("partial HTTP request: \n%s\n",
                                           payloadAsAscii);

                                    struct HTTPCacheEntry *newEntry =
                                            createHTTPCacheEntry(srcaddress,
                                                                 destaddress, &sport_num,
                                                                 payloadAsAscii);
                                    newEntry->lastseqnum = &tcpsequencenum;
                                    hashmap_insert_entry(key, newEntry, HTTPCache);

                                } else {
                                    printf("HTTP payload: \n %s \n", payloadAsAscii);
                                    inspectHTTPData(payloadAsAscii, strlen(payloadAsAscii), srcaddress, destaddress);

                                }

                            }


                        }

                    }


                }


            }
	    //if the SYN flag is set and NOT the ack then this is a pure SYN

            if (tcp->th_flags & TH_SYN && !(tcp->th_flags & TH_ACK == 1)) {
                isSYN = 1;
                traceInts->syn_count++;
                isconnecting = 1;
            }

	    //otherwise if the ACK is set this counts as an ack

            else if (tcp->th_flags & TH_ACK || (tcp-> th_flags & TH_SYN) && (tcp-> th_flags & TH_ACK)){
                traceInts->ack_count++;
                isACK = 1;
                isconnecting = 0;

            }
            if (tcp->th_flags & TH_FIN) {
                traceInts->fin_count++;
            }


            break;

        case IPPROTO_UDP:
            traceInts->UDP_count++;
            struct udphdr *udp = (struct udphdr *) (packet + ethersize
                                                    + (ip->ip_hl * 4));

            sport_num = ntohs(udp->uh_sport);

            dport_num = ntohs(udp->uh_dport);

            break;
        case IPPROTO_ICMP:
            traceInts->icmp_count++;
            struct icmphdr *icmp = (struct icmphdr *) (packet + ethersize
                                                       + (ip->ip_hl * 4));
            switch (icmp->type) {
                case ICMP_ECHO:
                    traceInts->ping_req_count++;
                    break;
                case ICMP_ECHOREPLY:
                    traceInts->ping_rep_count++;
                    break;
                case ICMP_DEST_UNREACH:
                    if (icmp->code == 3) {
                        isUnreachable = 1;
                        traceInts->port_error_count++;
                    }
                    break;
            }
            break;
    }

    char *key = createKey(srcaddress, destaddress, &sport_num, &dport_num,
                          &protocolnum);

    int entryPlace = hashmap_get_hash(key, storedFlows->size);

    entry *entry = storedFlows->table[entryPlace];

    if (entry == NULL) {
        struct flowInfo *newFlow = create_flow(srcaddress, destaddress,
                                               ip->ip_p, sport_num, dport_num, pktTimeStamp, &totalsize, isUnreachable,
                                               isSYN, isACK);
        if (dport_num == 80 && isconnecting) {
            newFlow->
                    num_HTTP_connections = 1;
        }

        assert(newFlow != NULL);
        hashmap_insert_entry(key, newFlow, storedFlows
        );
    }

    else {

        struct flowInfo *entryData = (struct flowInfo *) entry->data;
        entryData->byte_count +=
                totalsize;
        entryData->num_pkts += 1;


        entryData->time_inactive += *pktTimeStamp - entryData->
                lastRecivedTime;

        //inductivley, the time that this address has been active is the current time minus the time inactive

        entryData->time_active += *pktTimeStamp - entryData->
                time_inactive;

        entryData->
                lastRecivedTime = *pktTimeStamp;

        if (dport_num == 80) {

            entryData->num_HTTP_connections +=
                    isconnecting;

            double HTTP_Connection_Percentage = 0.00;

            if (totalHTTPconnections > 0) {
                HTTP_Connection_Percentage = ((double) entryData->num_HTTP_connections
                                              / (double) totalHTTPconnections) * 100;
            }

            entryData->
                    percentageHTTPConnectionsheld = HTTP_Connection_Percentage;

            char *HTTPdatastring = malloc(100 * sizeof(char));
            sprintf(HTTPdatastring,
                    "%.2f", entryData->time_active);
            sprintf(&HTTPdatastring[
                    strlen(HTTPdatastring)
            ], "%c", ',');
            sprintf(&HTTPdatastring[
                            strlen(HTTPdatastring)
                    ], "%.2f",
                    entryData->time_inactive);
            sprintf(&HTTPdatastring[
                    strlen(HTTPdatastring)
            ], "%c", ',');
            sprintf(&HTTPdatastring[
                            strlen(HTTPdatastring)
                    ], "%.2f",
                    entryData->percentageHTTPConnectionsheld);
            sprintf(&HTTPdatastring[
                    strlen(HTTPdatastring)
            ], "%c", '\n');

            if (trainingenabled) {
                traceToFile(HTTPdatastring,
                            "HTTPstats");
            } else {
                //classifydata(HTTPdatastring, "/HTTPListener", "HTTPDATA");
            }

        }
    }


    return 1;
}

int _runmode_train(char *sniffing_device) {

    const char *types[] = {"SYN FLOOD", "UDP FLOOD", "ICMP FLOOD", "SMURF ATTACK",
                           "SLOW HTTP", "NORMAL TRAFFIC"};
    trainingenabled = 1;

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
        for (i = 0; i < 6; i++) {
            printf("%s \n", types[i]);
        }
        scanf("%s", type);

        struct timedTrace *trace = (struct timedTrace *) malloc(
                sizeof(struct timedTrace));
        i = 0;
        if (strcmp(type, "SLOWHTTP") == 0) {
            printf("collecting HTTP samples, type 'e' to end \n");
            while (1) {
                samplepackets(trace);
            }

        } else {
            printf("please enter the number of samples to be collected:");
            scanf("%d", &samplesize);
            printf("OK, gathering %d samples for %s traffic \n", samplesize,
                   type);
            while (i < samplesize) {
                memset(trace, 0, sizeof(struct timedTrace));
                samplepackets(trace);
                char *trace_as_string = trace_to_string(trace);
                char *str1 = strcat(trace_as_string, type);
                char *final = strcat(str1, "\n");
                printf("sample %s", final);
                traceToFile(final, "trainingdata");
                printf("\r finished sample %d of %d \n", i + 1, samplesize);
                fflush(stdout);
                i++;
            }

            free(trace);
            puts("\n");
            puts("done sampling");
        }
    }
    return 1;
}

void _runmode_test(char *sniffing_device) {
    if (createHandle(sniffing_device) < 0) {
        perror("could not create handle");
    }
    struct timedTrace *trace = (struct timedTrace *) malloc(
            sizeof(struct timedTrace));

    puts("monitoring network traffic...");

    while (1) {
        memset(trace, 0, sizeof(struct timedTrace));
        samplepackets(trace);
        //classifydata(trace_to_string(trace), "/classifierstream", "QUANTATIVEDATA");
    }

}

void __setup__() {
    gettimeofday(&sample_start_time, NULL);
    storedFlows = hashmap_createMap(1000);
    HTTPCache = hashmap_createMap(50);
    compileSQLRegex();
}

void __teardown__() {
    free(storedFlows);
    free(HTTPCache);
}

void testReachability() {
    assert(checkReachability("139.184.49.241") > 0);
    puts("passed traceroute test for good address");
    assert(checkReachability("10.2.7.877") == 0);
    puts("passed traceroute test for bad address");
    struct PingArgs args;
    struct timedTrace *trace = (struct timedTrace *) malloc(
            sizeof(struct timedTrace));
    args.sourceAddress = goodSource;
    args.trace = trace;

    getPingStats(&args);

    //testing this on an address that we know will reply
    assert(trace->ping_packet_loss == 0.00);
    puts("passed ping test for good host");
    printf("%.2f \n", trace->average_RTT_to_known_host);

}

void testAlert() {
    struct timeval testtime;
    gettimeofday(&testtime, NULL);
    char *target1 = "152.168.2.1";
    char *target2 = "152.168.2.2";
    double emptytime = 0.00;
    int emptyval = 0;
    struct flowInfo *testFlow1 = create_flow("172.16.51.201", target1, IPPROTO_TCP, 0, 0, &emptytime, &emptyval, 0, 0, 0);
    struct flowInfo *testFlow2 = create_flow("172.16.51.201", target2, IPPROTO_TCP, 0, 0, &emptytime, &emptyval, 0, 0, 0);
    listnode *head = linkedList_add(NULL, testFlow1);
    linkedList_add(head, testFlow2);
    createAlert("SYN FLOOD", &testtime, head);

}

void displayMenu() {
    int chosen;
    char device[20];
    printf("capture device: ");
    scanf("%s", device);
    printf("runmode (select 0 for training, 1 for live):");
    scanf("%d", &chosen);
    switch (chosen) {
        case 0:
            __setup__();
            _runmode_train(device);
            __teardown__();
            return;
        case 1:
            __setup__();
            _runmode_test(device);
            __teardown__();
            return;
        default:
            exit(1);

    }
}

int main() {
    //testReachability();
    //testAlert();
    displayMenu();
    return 0;
}


