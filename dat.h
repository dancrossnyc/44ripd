#ifndef RIPD_DAT_H
#define RIPD_DAT_H

#include <inttypes.h>
#include <stddef.h>
#include <time.h>

typedef unsigned char octet;
typedef struct Route Route;
typedef struct Tunnel Tunnel;

struct Route {
	uint32_t ipnet;
	uint32_t subnetmask;
	uint32_t gateway;
	time_t expires;		// Seconds.
	Route *rnext;
	Tunnel *tunnel;
};

enum {
	MAX_TUN_IFNAME = 16,
};

struct Tunnel {
	Route *routes;
	uint32_t outer_local;
	uint32_t outer_remote;
	uint32_t inner_local;
	uint32_t inner_remote;
	int nref;
	char ifname[MAX_TUN_IFNAME];
	unsigned int ifnum;
};

#endif
