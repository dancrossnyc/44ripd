#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dat.h"
#include "fns.h"

int
parserippkt(const octet *restrict data, size_t len, RIPPacket *restrict packet)
{
	assert(data != NULL);
	assert(packet != NULL);
	if (len < MIN_RIP_PACKET_SIZE)
		return -1;
	packet->command = data[0];
	packet->version = data[1];
	packet->nbz     = readnet16(data + 2);
	packet->datalen = len - MIN_RIP_PACKET_SIZE;
	packet->data    = NULL;
	if (packet->datalen != 0)
		packet->data = data + 4;
	if ((packet->datalen % RIP_RESPONSE_SIZE) != 0)
		return -1;
	packet->nresponse = packet->datalen / RIP_RESPONSE_SIZE;

	return 0;
}

int
verifyripauth(RIPPacket *restrict packet, const char *restrict password)
{
	char packetpass[16 + 1];

	assert(packet != NULL);
	assert(password != NULL);
	if (packet->datalen < RIP_RESPONSE_SIZE)
		return -1;
	if (readnet16(packet->data + 0) != 0xFFFF)
		return -1;
	if (readnet16(packet->data + 2) != 2)
		return -1;
	memmove(packetpass, (char *)packet->data + 4, 16);
	packetpass[16] = '\0';
	if (strcmp(packetpass, password) != 0)
		return -1;
	--packet->nresponse;
	packet->data += RIP_RESPONSE_SIZE;
	packet->datalen -= RIP_RESPONSE_SIZE;

	return 0;
}

static int
parseriprespocts(const octet *data, size_t len, RIPResponse *restrict response)
{
	assert(data != NULL);
	assert(response != NULL);
	if (len < RIP_RESPONSE_SIZE)
		return -1;
	response->addrfamily = readnet16(data +  0);
	response->routetag   = readnet16(data +  2);
	response->ipaddr     = readnet32(data +  4);
	response->subnetmask = readnet32(data +  8);
	response->nexthop    = readnet32(data + 12);
	response->metric     = readnet32(data + 16);
	if (!isvalidnetmask(response->subnetmask))
		return -1;

	return 0;
}

int
parseripresponse(const RIPPacket *restrict packet, int k,
    RIPResponse *restrict response)
{
	size_t offset;

	assert(packet != NULL);
	assert(response != NULL);
	offset = k*RIP_RESPONSE_SIZE;
	if (packet->datalen < offset)
		return -1;
	return parseriprespocts(packet->data + offset,
	           packet->datalen - offset, response);
}
