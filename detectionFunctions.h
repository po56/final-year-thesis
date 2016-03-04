#ifndef _DETECTIONFUNCS_H_
#define _DETECTIONFUNCS_H_

#include <stdlib.h>
#include <stdio.h>

#define tcp_rel_percentage(traceIntegers, var) (var/((traceIntegers)->tcp_count))
#define pkt_type_per_sec(traceIntegers,member,recordTime) ((traceIntegers)->member/recordTime)
#define zerocheck(traceIntegers, member, function)(((traceIntegers)->member) > 0 ? (function) : 0.00)

struct DArray{
	unsigned char *members;
	size_t used;
	size_t size;
};

struct flowInfo{
	char *srcAddress;
	char *destAddress;
	char *protocol;
	int sourcePort;
	int destPort;
	double lastRecivedTime;
	double time_active;
	double time_inactive;
	int numberOfConnections;
	int byte_count;
	int num_pkts;
};

struct timedTrace {
	double icmp_persec;
	unsigned int unique_sources;
	double tcp_syn_percentage;
	double tcp_ack_percentage;
	double tcp_fin_percentage;
	int port_errors;
	int ping_requests;
	int ping_replies;
	double average_RTT_to_known_host;
	double ping_packet_loss;
};

struct traceIntegers {
	double icmp_count, tcp_count, syn_count, ack_count, fin_count,
			UDP_count;
	int ping_req_count, ping_rep_count, source_count, port_error_count;

};

struct PingArgs {
	struct timedTrace *trace;
	char *sourceAddress;
};

double calculateTimeActive(time_t *time1);

double calculateTimeInactive(time_t *time1, time_t *time2);

int attemptTraceroute(char *srcaddress);

void investigatePacket(const unsigned char *packet);

int classifyTrace();

int train(char *sniffing_device);

int test(char *sniffing_device);

int samplepackets(struct timedTrace *trace);

int shallow_inspect_pkt(const unsigned char *packet, struct traceIntegers *traceInts, double *pktTimeStamp);

unsigned char *parseToAscii(const unsigned char *payload, int len);

int deep_inspect_pkt(const unsigned char *packet);

int inspect_HTTP(const unsigned char *asciiText, int payload_len);

int createHandle(char *sniffingdevice);

char *createKey(char *srcAddress, char *destAddress, int *srcPort, int *destPort, int *proto);

void createReport(int classificationResult, time_t currentTime);

void trace_to_file(char *type);

void *getPingStats(void *args);

double averageRTT(double times[], int nSamples, int iterator);

int classify(struct timedTrace *trace);

#endif


