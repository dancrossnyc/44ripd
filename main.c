/*
 * This is an OpenBSD daemon for a modified version of the RIPv2
 * protocol (RFC 2453).  It is designed to handle route and
 * tunnel maintenance for the AMPR amateur radio network
 * (IPv4 44/8: http://www.ampr.org).  Note that the AMPRNet is a
 * mesh: each site sets up IPENCAP tunnels to (almost) all other
 * sites.
 *
 * The daemon listens on a multicast socket for UDP datagrams
 * directed to the RIP port.  It discards packets that are not
 * valid, authenticated RIP packets (though authentication is
 * simply string comparison against a plaintext password: it is
 * not particularly strong and could be trivially broken).  It
 * maintains an internal copy of the AMPRNet routing table as
 * well as a set of active tunnels.
 *
 * After processing a RIP packet, the daemon walks through the
 * routing table, looking for routes to expire.  If a route
 * expires it is noted for removal from the table.  Expiration
 * time is much greater than the expected interval between
 * RIP broadcasts.
 *
 * Routes keep a reference to a tunnel.  When a route is added
 * that refers to an non-existent tunnel, the tunnel is created
 * and set up.  If a route referring to a tunnel is removed or
 * changed to a different tunnel, the tunnel's reference count
 * is decremented. If a tunnel's reference count drops to zero,
 * it is torn down and removed.
 *
 * Each tunnel corresponds to a virtual IP encapsulation
 * interface; see gif(4) for details.  The daemon dynamically
 * creates and destroys these interfaces as required.  A bitmap
 * of active interfaces is kept and the lowest unused interface
 * number is always allocated when a new tunnel is created.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dat.h"
#include "fns.h"

int init(int argc, char *argv[]);
unsigned int strnum(const char *restrict str);
void riptide(int sd);
void ripresponse(RIPResponse *response, time_t now);
Route *mkroute(uint32_t ipnet, uint32_t subnetmask, uint32_t gateway);
Tunnel *mktunnel(uint32_t local, uint32_t remote);
void alloctunif(Tunnel *tunnel, Bitvec *interfaces);
void unlinkroute(Tunnel *tunnel, Route *route);
void linkroute(Tunnel *tunnel, Route *route);
void walkexpired(time_t now);
void destroy(uint32_t key, size_t keylen, void *routep, void *unused);
void expire(uint32_t key, size_t keylen, void *routep, void *statep);
void usage(const char *restrict prog);

enum {
	CIDR_HOST = 32,
	RIPV2_PORT = 520,
	DEFAULT_ROUTE_TABLE = 44,
	TIMEOUT = 7*24*60*60,	// 7 days
};

const char *DEFAULT_LOCAL_ADDRESS = "23.30.150.141";
const char *RIPV2_GROUP = "224.0.0.9";
const char *PASSWORD = "pLaInTeXtpAsSwD";

IPMap *ignoreroutes;
IPMap *routes;
IPMap *tunnels;
Bitvec *interfaces;
Bitvec *staticinterfaces;

const char *prog;
uint32_t localaddr;
int routetable;
int lowgif;

int
main(int argc, char *argv[])
{
	int sd;

	sd = init(argc, argv);
	for (;;)
		riptide(sd);
	close(sd);

	return 0;
}

int
init(int argc, char *argv[])
{
	const char *localip;
	char *slash;
	int sd, ch, daemonize;
	struct in_addr addr;

	slash = strrchr(argv[0], '/');
	prog = (slash == NULL) ? argv[0] : slash + 1;
	daemonize = 1;
	interfaces = mkbitvec();
	staticinterfaces = mkbitvec();
	routetable = DEFAULT_ROUTE_TABLE;
	localip = DEFAULT_LOCAL_ADDRESS;
	routes = mkipmap();
	tunnels = mkipmap();
	while ((ch = getopt(argc, argv, "dT:L:I:s:")) != -1) {
		switch (ch) {
		case 'd':
			daemonize = 0;
			break;
		case 'T':
			routetable = strnum(optarg);
			break;
		case 'L':
			localip = optarg;
			break;
		case 'I': {
			static void *IGNORE = (void *)0x10;	// Arbitrary.
			uint32_t iroute;
			size_t icidr;

			slash = strchr(optarg, '/');
			if (slash == NULL)
				fatal("Bad route (use CIDR): %s\n", optarg);
			*slash++ = '\0';
			iroute = strnum(optarg);
			icidr = strnum(slash);
			ipmapinsert(ignoreroutes, iroute, icidr, IGNORE);
			break;
		}
		case 's': {
			unsigned int ifnum = strnum(optarg);
			bitset(staticinterfaces, ifnum);
			bitset(interfaces, ifnum);
			break;
		}
		case '?':
		case 'h':
		default:
			usage(prog);
		}
	}
	initsys(routetable);
	sd = initsock(RIPV2_GROUP, RIPV2_PORT, routetable);
	memset(&addr, 0, sizeof(addr));
	inet_pton(AF_INET, localip, &addr);
	localaddr = addr.s_addr;

	initlog();
	if (daemonize)
		daemon(0, 1);

	return sd;
}

enum {
	MAX_NUM = (1 << 20),
};

unsigned int
strnum(const char *restrict str)
{
	char *ep;
	unsigned long r;

	ep = NULL;
	r = strtoul(str, &ep, 10);
	if (ep != NULL && *ep != '\0')
		fatal("bad unsigned integer: %s", str);
	if (r > MAX_NUM)
		fatal("integer range error: %s", str);

	return (unsigned int)r;
}


void
riptide(int sd)
{
	struct sockaddr *rem;
	struct sockaddr_in remote;
	socklen_t remotelen;
	ssize_t n;
	time_t now;
	RIPPacket pkt;
	octet packet[IP_MAXPACKET];

	memset(&remote, 0, sizeof(remote));
	remotelen = 0;
	rem = (struct sockaddr *)&remote;
	n = recvfrom(sd, packet, sizeof(packet), 0, rem, &remotelen);
	if (n < 0)
		fatal("socket error");
	memset(&pkt, 0, sizeof(pkt));
	if (parserippkt(packet, n, &pkt) < 0) {
		error("packet parse error\n");
		return;
	}
	if (verifyripauth(&pkt, PASSWORD) < 0) {
		error("packet authentication failed\n");
		return;
	}
	now = time(NULL);
	for (int k = 0; k < pkt.nresponse; k++) {
		RIPResponse response;
		memset(&response, 0, sizeof(response));
		if (parseripresponse(&pkt, k, &response) < 0) {
			notice("bad response, index %d\n", k);
			continue;
		}
		ripresponse(&response, now);
	}
	walkexpired(now);
}

void
ripresponse(RIPResponse *response, time_t now)
{
	Route *route;
	Tunnel *tunnel;
	size_t cidr;
	char proute[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];

	cidr = netmask2cidr(response->subnetmask);
	inet_ntop(AF_INET, &response->ipaddr, proute, sizeof(proute));
	inet_ntop(AF_INET, &response->nexthop, gw, sizeof(gw));
	if (response->ipaddr & ~response->subnetmask)
		error("route ipaddr %s has more bits than netmask, %zu",
		    proute, cidr);
	response->ipaddr &= response->subnetmask;
	if (response->nexthop == localaddr) {
		error("skipping route for %s/%zu to local address",
		    proute, cidr);
		return;
	}
	if ((response->nexthop & response->ipaddr) == response->nexthop) {
		error("skipping gateway inside of subnet (%s/%zu -> %s)",
		    proute, cidr, gw);
		return;
	}
	tunnel = ipmapfind(tunnels, response->nexthop, CIDR_HOST);
	if (tunnel == NULL) {
		tunnel = mktunnel(localaddr, response->nexthop);
		alloctunif(tunnel, interfaces);
		uptunnel(tunnel, routetable);
		ipmapinsert(tunnels, response->nexthop, CIDR_HOST, tunnel);
	}
	route = ipmapfind(routes, response->ipaddr, cidr);
	if (route == NULL) {
		route = mkroute(
		    response->ipaddr,
		    response->subnetmask,
		    response->nexthop);
		ipmapinsert(routes, route->ipnet, cidr, route);
		info("added route");
	}
	// The route is new or moved to a different tunnel.
	if (route->tunnel != tunnel) {
		if (route->tunnel == NULL)
			addroute(route, tunnel, routetable);
		else
			chroute(route, tunnel, routetable);
		unlinkroute(tunnel, route);
		unlinkroute(route->tunnel, route);
		linkroute(tunnel, route);
	}
	route->expires = now + TIMEOUT;
	debug("RIPv2 response: %s/%zu -> %s\n", proute, cidr, gw);
}

Route *
mkroute(uint32_t ipnet, uint32_t subnetmask, uint32_t gateway)
{
	Route *route;

	route = calloc(1, sizeof(*route));
	if (route == NULL)
		fatal("malloc");
	route->ipnet = ipnet;
	route->subnetmask = subnetmask;
	route->gateway = gateway;

	return route;
}

Tunnel *
mktunnel(uint32_t local, uint32_t remote)
{
	Tunnel *tunnel;

	tunnel = calloc(1, sizeof(*tunnel));
	if (tunnel == NULL)
		fatal("malloc");
	tunnel->local = local;
	tunnel->remote = remote;

	return tunnel;
}

void
alloctunif(Tunnel *tunnel, Bitvec *interfaces)
{
	size_t ifnum;

	ifnum = nextbit(interfaces);
	tunnel->ifnum = ifnum;
	snprintf(tunnel->ifname, sizeof(tunnel->ifname), "gif%zu", ifnum);
	bitset(interfaces, ifnum);
}

void
unlinkroute(Tunnel *tunnel, Route *route)
{
	if (tunnel == NULL)
		return;
	for (Route *prev = NULL, *tmp = tunnel->routes;
	    tmp != NULL;
	    prev = tmp, tmp = tmp->rnext)
	{
		if (route->ipnet == tmp->ipnet &&
		    route->subnetmask == tmp->subnetmask)
		{
			if (prev == NULL)
				tunnel->routes = tmp->rnext;
			else
				prev->rnext = tmp->rnext;
			route->gateway = 0;
			--tunnel->nref;
			break;
		}
	}
}

void
linkroute(Tunnel *tunnel, Route *route)
{
	route->rnext = tunnel->routes;
	tunnel->routes = route;
	route->tunnel = tunnel;
	route->gateway = tunnel->remote;
	++tunnel->nref;
}

typedef struct WalkState WalkState;
struct WalkState {
	time_t now;
	IPMap *deleting;
};

void
walkexpired(time_t now)
{
	WalkState state = { now, NULL };

	ipmapdo(routes, expire, &state);
	if (state.deleting != NULL) {
		ipmapdo(state.deleting, destroy, NULL);
		freeipmap(state.deleting, free);
	}
}

void
expire(uint32_t key, size_t keylen, void *routep, void *statep)
{
	Route *route = routep;
	WalkState *state = statep;

	if (route->expires > state->now)
		return;

	if (state->deleting == NULL)
		state->deleting = mkipmap(); 
	ipmapinsert(state->deleting, key, keylen, route);
}

void
destroy(uint32_t key, size_t keylen, void *routep, void *unused)
{
	Route *route = routep;
	Tunnel *tunnel;
	void *datum;

	(void)unused;
	if (route == NULL)
		return;
	datum = ipmapremove(routes, key, keylen);
	assert(datum == route);
	tunnel = route->tunnel;
	assert(tunnel != NULL);
	unlinkroute(tunnel, route);
	rmroute(route, routetable);
	assert(tunnel->nref >= 0);
	if (tunnel->nref == 0) {
		datum = ipmapremove(tunnels, tunnel->remote, CIDR_HOST);
		assert(datum == tunnel);
		downtunnel(tunnel);
		bitclr(interfaces, tunnel->ifnum);
		free(tunnel);
	}
}

void
usage(const char *restrict prog)
{
	fprintf(stderr,
	    "Usage: %s [ -d ] [ -T rtable ] [ -L local_ip ] "
	        "[ -I ignore ] [ -s static_ifnum ]\n",
	    prog);
	exit(EXIT_FAILURE);
}