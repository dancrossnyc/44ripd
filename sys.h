#ifndef RIPD_SYS_H
#define RIPD_SYS_H

//
// Operating system-specific helper functions.
//
#include <inttypes.h>

typedef void (*if_discovered_thunk)(const char *name, int num,
    uint32_t outer_local, uint32_t outer_remote, uint32_t inner_local,
    uint32_t inner_remote, void *arg
);
typedef void (*rt_discovered_thunk)(uint32_t ipnet, uint32_t mask,
    int isaddr, uint32_t dstaddr, const char *dstif, void *arg);
        
void discover(int rtable, if_discovered_thunk ifthunk,
    rt_discovered_thunk rtthunk, void *arg);
int initsock(const char *restrict group, int port, int rtable);
void initsys(int rtable);
int uptunnel(Tunnel *tunnel, int rtable);
int downtunnel(Tunnel *tunnel);
int addroute(Route *route, Tunnel *tunnel, int rtable);
int chroute(Route *route, Tunnel *tunnel, int rtable);
int rmroute(Route *route, int rtable);

#endif
