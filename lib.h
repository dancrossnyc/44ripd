#ifndef RIPD_LIB_H
#define RIPD_LIB_H

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdbool.h>

typedef struct Bitvec Bitvec;
typedef struct IPMap IPMap;
typedef struct RIPPacket RIPPacket;
typedef struct RIPResponse RIPResponse;

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

bool isvalidnetmask(uint32_t netmask);
int netmask2cidr(uint32_t netmask);
uint32_t revbits(uint32_t w);
IPMap *mkipmap(void);
void freeipmap(IPMap *map, void (*freedatum)(void *));
void ipmapdo(IPMap *map, int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg), void *arg);
void *ipmapinsert(IPMap *map, uint32_t key, size_t keylen, void *datum);
void *ipmapremove(IPMap *map, uint32_t key, size_t keylen);
void *ipmapnearest(IPMap *map, uint32_t key, size_t keylen);
void *ipmapfind(IPMap *map, uint32_t key, size_t keylen);
void ipaddrstr(uint32_t addr, char buf[static INET_ADDRSTRLEN]);
Bitvec *mkbitvec(void);
void freebitvec(Bitvec *bits);
int bitget(const Bitvec *bits, size_t bit);
void bitset(Bitvec *bits, size_t bit);
void bitclr(Bitvec *bits, size_t bit);
size_t nextbit(Bitvec *bits);

#ifdef USE_COMPAT
void *reallocarray(void *p, size_t nelem, size_t size);
#endif  // USE_COMPAT

#endif
