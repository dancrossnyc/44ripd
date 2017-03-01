#include <inttypes.h>
#include <stddef.h>
#include <time.h>

typedef unsigned char octet;
typedef struct Bitvec Bitvec;
typedef struct IPMap IPMap;
typedef struct RIPPacket RIPPacket;
typedef struct RIPResponse RIPResponse;
typedef struct Route Route;
typedef struct Tunnel Tunnel;

enum {
	MIN_RIP_PACKET_SIZE = 4,
};

/*
 * We use a bit vector to keep track of allocated interfaces.
 */
struct Bitvec {
	uint64_t *words;
	size_t nwords;
	size_t firstclr;
};

/*
 * A PATRICIA trie mapping CIDR network numbers to a datum.
 * The central data structure for maintaining lookup tables
 * of active routes and tunnels.
 */
struct IPMap {
	uint32_t key;
	size_t keylen;
	void *datum;
	IPMap *left;
	IPMap *right;
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
