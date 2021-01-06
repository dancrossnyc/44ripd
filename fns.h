#include <arpa/inet.h>

#include <inttypes.h>
#include <stdbool.h>

uint32_t readnet32(const octet data[static 4]);
uint16_t readnet16(const octet data[static 2]);
int parserippkt(const octet *restrict data, size_t len, RIPPacket *restrict packet);
int verifyripauth(RIPPacket *restrict packet, const char *restrict password);
int parseripresponse(const RIPPacket *restrict pkt, int k, RIPResponse *restrict response);
bool isvalidnetmask(uint32_t netmask);
unsigned int netmask2cidr(uint32_t netmask);
uint32_t cidr2netmask(unsigned int cidr);
uint32_t revbits(uint32_t w);
IPMap *mkipmap(void);
void freeipmap(IPMap *map, void (*freedatum)(void *));
int ipmapdo_preorder(IPMap *map, int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg), void *arg);
int ipmapdo_inorder(IPMap *map, int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg), void *arg);
int ipmapdo_postorder(IPMap *map, int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg), void *arg);
void ipmapdo(IPMap *map, void (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg), void *arg);
void *ipmapinsert(IPMap *map, uint32_t key, size_t keylen, void *datum);
void *ipmapremove(IPMap *map, uint32_t key, size_t keylen);
void *ipmapnearest(IPMap *map, uint32_t key, size_t keylen);
void *ipmapfind(IPMap *map, uint32_t key, size_t keylen);
int initsock(const char *restrict iface, const char *restrict group, int port, int rtable);
void initsys(int rtable);
int uptunnel(Tunnel *tunnel, int rdomain, int tunneldomain, uint32_t endpoint);
int downtunnel(Tunnel *tunnel);
int addroute(Route *route, Tunnel *tunnel, int rtable);
int chroute(Route *route, Tunnel *tunnel, int rtable);
int rmroute(Route *route, int rtable);
void ipaddrstr(uint32_t addr, char buf[static INET_ADDRSTRLEN]);
void routestr(Route *route, Tunnel *tunnel, char *buf, size_t size);
Bitvec *mkbitvec(void);
void freebitvec(Bitvec *bits);
int bitget(Bitvec *bits, size_t bit);
void bitset(Bitvec *bits, size_t bit);
void bitclr(Bitvec *bits, size_t bit);
size_t nextbit(Bitvec *bits);
unsigned int strnum(const char *restrict str);

void initlog(void);
void debug(const char *restrict fmt, ...);
void info(const char *restrict fmt, ...);
void notice(const char *restrict fmt, ...);
void error(const char *restrict fmt, ...);
void fatal(const char *restrict fmt, ...);

#ifdef USE_COMPAT
void *reallocarray(void *p, size_t nelem, size_t size);
void *recallocarray(void *p, size_t oelem, size_t nelem, size_t size);
#endif  // USE_COMPAT
