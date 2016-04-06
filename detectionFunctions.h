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
	int tcpSYNSTransmiteed;
	int tcpACKSTransmitted;
	int unreachableErrorsInvoked;
	double lastRecivedTime;
	double time_active;
	double time_inactive;
	double percentageHTTPConnectionsheld;
	int num_HTTP_connections;
	int byte_count;
	int num_pkts;
};

struct SQLi{
	char *src;
	char *dst;
	char *str;
	char *reason;
};

struct threatReport{
	char *type;
	time_t timestamp;
	void *data;
};

typedef struct HTTPrequest{
	char *method;
	char *URI;
	char *version;
	char *messagebody;
}HTTPRequest;

struct HTTPCacheEntry{
	char *srcAddress;
	char *destAddress;
	int *sourcePort;
	const char *truncated_data;
	int *lastseqnum;
};


struct timedTrace {
	double icmp_persec;
	unsigned int unique_sources;
	double tcp_syn_percentage;
	double tcp_ack_percentage;
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


int _runmode_train(char *sniffing_device);

void _runmode_test(char *sniffing_device);

int samplepackets(struct timedTrace *trace);

int packet_fragmentation_check(struct ip *ip, int headerlen);

int shallow_inspect_pkt(const unsigned char *packet, struct traceIntegers *traceInts, double *ts, int totalpktsize);

unsigned char *parseToAscii(const unsigned char *payload, int len);

void inspectHTTPData(const char *HTTPacket, int payload_len, char *source, char *dest);

int createHandle(char *sniffingdevice);

char *createKey(char *srcAddress, char *destAddress, int *srcPort, int *destPort, int *proto);

void *getPingStats(void *args);

void parseSQL(char *packetdata, char *src, char *dest);

double averageRTT(double times[], int nSamples, int iterator);


#endif

