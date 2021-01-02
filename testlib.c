#include <sys/types.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dat.h"
#include "fns.h"

uint32_t
mkkey(const char *addr)
{
	return ntohl(inet_addr(addr));
}

size_t
mkkeylen(const char *subnetmask)
{
	in_addr_t netmask = ntohl(inet_addr(subnetmask));
	assert(isvalidnetmask(netmask));
	return netmask2cidr(netmask);
}

void
u32tobin(uint32_t w, size_t len, char bin[static 33])
{
	assert(len <= 32);
	for (int k = 0; k < len; k++)
		bin[k] = '0' + ((w >> k) & 0x01);
	bin[len] = '\0';
}
