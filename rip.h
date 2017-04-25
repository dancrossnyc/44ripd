#ifndef RIPD_RIP_H
#define RIPD_RIP_H

#include <inttypes.h>
#include <stdbool.h>

#include "dat.h"

typedef struct RIPPacket RIPPacket;
typedef struct RIPResponse RIPResponse;

enum {
	MIN_RIP_PACKET_SIZE = 4,
};

struct RIPPacket {
	octet command;
	octet version;
	uint16_t nbz;
	size_t datalen;
	size_t nresponse;
	const octet *data;
};

enum {
	RIP_RESPONSE_SIZE = 20,
};

struct RIPResponse {
	uint16_t addrfamily;
	uint16_t routetag;
	uint32_t ipaddr;
	uint32_t subnetmask;
	uint32_t nexthop;
	uint32_t metric;
};

int parserippkt(const octet *restrict data, size_t len, RIPPacket *restrict packet);
int verifyripauth(RIPPacket *restrict packet, const char *restrict password);
int parseripresponse(const RIPPacket *restrict pkt, int k, RIPResponse *restrict response);

#endif
