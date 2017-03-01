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
#include <fcntl.h>
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
Tunnel *mktunnel(uint32_t outer_local, uint32_t outer_remote,
    uint32_t inner_local, uint32_t inner_remote);
void alloctunif(Tunnel *tunnel, Bitvec *interfaces);
void unlinkroute(Tunnel *tunnel, Route *route);
void linkroute(Tunnel *tunnel, Route *route);
void walkexpired(time_t now);
void destroy(uint32_t key, size_t keylen, void *routep, void *unused);
void collapse(Tunnel *tunnel);
void expire(uint32_t key, size_t keylen, void *routep, void *statep);
void usage(const char *restrict prog);

enum {
	CIDR_HOST = 32,
	RIPV2_PORT = 520,
	DEFAULT_ROUTE_TABLE = 44,
	TIMEOUT = 7*24*60*60,	// 7 days
};

static const char *RIPV2_GROUP = "224.0.0.9";
static const char *PASSWORD = "pLaInTeXtpAsSwD";

static void * const IGNORE = (void *)0x10;	// Arbitrary.
static void * const ACCEPT = (void *)0x11;	// Arbitrary.

static IPMap *acceptableroutes;
static IPMap *routes;
static IPMap *tunnels;
static Bitvec *interfaces;
static Bitvec *staticinterfaces;

static const char *prog;
static uint32_t local_outer_addr;
static uint32_t local_inner_addr;
static int routetable_bind, routetable_create;
static int read_from_file;

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
	const char *local_outer_ip, *local_inner_ip;
	char *slash;
	int sd, ch, daemonize, acceptcount;
	struct in_addr addr;

	slash = strrchr(argv[0], '/');
	prog = (slash == NULL) ? argv[0] : slash + 1;
	daemonize = 1;
	read_from_file = 0;
	interfaces = mkbitvec();
	staticinterfaces = mkbitvec();
	routetable_create = DEFAULT_ROUTE_TABLE;
	routetable_bind = DEFAULT_ROUTE_TABLE;
	local_outer_ip = NULL;
	local_inner_ip = NULL;
	routes = mkipmap();
	tunnels = mkipmap();
	acceptableroutes = mkipmap();
	acceptcount = 0;
	while ((ch = getopt(argc, argv, "dT:A:B:I:s:f:")) != -1) {
		switch (ch) {
		case 'd':
			daemonize = 0;
			break;
		case 'T':
			routetable_create = strnum(optarg);
			break;
		case 'B':
			routetable_bind = strnum(optarg);
			break;
		case 'A':
		case 'I': {
			void *ignore_accept = (ch == 'A' ? ACCEPT : IGNORE);
			struct in_addr iroute;
			size_t icidr;

			slash = strchr(optarg, '/');
			if (slash == NULL)
				fatal("Bad route (use CIDR): %s\n", optarg);
			*slash++ = '\0';
			if (inet_aton(optarg, &iroute) != 1)
				fatal("Bad route addr: %s\n", optarg);
			iroute.s_addr = ntohl(iroute.s_addr);
			icidr = strnum(slash);
			ipmapinsert(acceptableroutes, iroute.s_addr, icidr,
			    ignore_accept);
			acceptcount++;
			break;
		}
		case 's': {
			unsigned int ifnum = strnum(optarg);
			bitset(staticinterfaces, ifnum);
			bitset(interfaces, ifnum);
			break;
		}
		case 'f': {
			if (read_from_file)
				fatal("Can only read from one file.\n");
			read_from_file = 1;
			sd = open(optarg, O_RDONLY);
			if (sd < 0)
				fatal("Can't open '%s'\n", optarg);
			break;
		}
		case '?':
		case 'h':
		default:
			usage(prog);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage(prog);

	if (acceptcount == 0)
		// Accept everything by default
		ipmapinsert(acceptableroutes, 0, 0, ACCEPT);

	local_outer_ip = argv[0];
	local_inner_ip = argv[1];

	initsys(routetable_create);

	if (!read_from_file)
		sd = initsock(RIPV2_GROUP, RIPV2_PORT, routetable_bind);

	memset(&addr, 0, sizeof(addr));

	inet_pton(AF_INET, local_outer_ip, &addr);
	local_outer_addr = ntohl(addr.s_addr);

	inet_pton(AF_INET, local_inner_ip, &addr);
	local_inner_addr = ntohl(addr.s_addr);

	initlog();
	if (daemonize) {
		const int no_chdir = 0;
		const int no_close = 0;
		daemon(no_chdir, no_close);
	}

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
	if (read_from_file) {
		n = read(sd, packet, sizeof(packet));
		if (n == 0)
			fatal("done");
	} else {
		n = recvfrom(sd, packet, sizeof(packet), 0, rem, &remotelen);
	}
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
	void *acceptance;
	Tunnel *tunnel;
	size_t cidr;
	char proute[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];

	cidr = netmask2cidr(response->subnetmask);
	ipaddrstr(response->ipaddr, proute);
	ipaddrstr(response->nexthop, gw);
	if (response->ipaddr & ~response->subnetmask)
		error("route ipaddr %s has more bits than netmask, %zu",
		    proute, cidr);
	response->ipaddr &= response->subnetmask;
	if (response->nexthop == local_outer_addr) {
		info("skipping route for %s/%zu to local address",
		    proute, cidr);
		return;
	}
	if ((response->nexthop & response->subnetmask) == response->ipaddr) {
		info("skipping gateway inside of subnet (%s/%zu -> %s)",
		    proute, cidr, gw);
		return;
	}
	acceptance = ipmapnearest(acceptableroutes, response->ipaddr, cidr);
	if (acceptance == NULL || acceptance != ACCEPT) {
		info("skipping ignored network %s/%zu", proute, cidr);
		return;
	}
	tunnel = ipmapfind(tunnels, response->nexthop, CIDR_HOST);
	if (tunnel == NULL) {
		tunnel = mktunnel(local_outer_addr, response->nexthop,
		    local_inner_addr, response->ipaddr);
		alloctunif(tunnel, interfaces);
		uptunnel(tunnel, routetable_create);
		ipmapinsert(tunnels, response->nexthop, CIDR_HOST, tunnel);
	}
	route = ipmapfind(routes, response->ipaddr, cidr);
	if (route == NULL) {
		route = mkroute(
		    response->ipaddr,
		    response->subnetmask,
		    response->nexthop);
		ipmapinsert(routes, route->ipnet, cidr, route);
		info("Added route %s/%zu -> %s", proute, cidr, gw);
	}
	// The route is new or moved to a different tunnel.
	if (route->tunnel != tunnel) {
		if (route->tunnel == NULL)
			addroute(route, tunnel, routetable_create);
		else
			chroute(route, tunnel, routetable_create);
		unlinkroute(tunnel, route);
		unlinkroute(route->tunnel, route);
		collapse(route->tunnel);
		linkroute(tunnel, route);
	}
	route->expires = now + TIMEOUT;
	debug("RIPv2 response: %s/%zu -> %s", proute, cidr, gw);
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
mktunnel(uint32_t outer_local, uint32_t outer_remote, uint32_t inner_local,
    uint32_t inner_remote)
{
	Tunnel *tunnel;

	tunnel = calloc(1, sizeof(*tunnel));
	if (tunnel == NULL)
		fatal("malloc");
	tunnel->outer_local = outer_local;
	tunnel->outer_remote = outer_remote;
	tunnel->inner_local = inner_local;
	tunnel->inner_remote = inner_remote;

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
	info("Allocating tunnel interface %s", tunnel->ifname);
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
	route->gateway = tunnel->inner_remote;
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
	size_t cidr;
	char proute[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];

	if (route->expires > state->now)
		return;

	if (state->deleting == NULL)
		state->deleting = mkipmap(); 
	cidr = netmask2cidr(route->subnetmask);
	assert(cidr == keylen);
	ipaddrstr(route->ipnet, proute);
	ipaddrstr(route->gateway, gw);
	info("Expiring route %s/%zu -> %s", proute, cidr, gw);
	ipmapinsert(state->deleting, key, keylen, route);
}

void
destroy(uint32_t key, size_t keylen, void *routep, void *unused)
{
	Route *route = routep;
	Tunnel *tunnel;
	void *datum;
	size_t cidr;
	char proute[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];

	(void)unused;
	if (route == NULL)
		return;
	cidr = netmask2cidr(route->subnetmask);
	assert(cidr == keylen);
	ipaddrstr(route->ipnet, proute);
	ipaddrstr(route->gateway, gw);
	info("Destroying route %s/%zu -> %s", proute, cidr, gw);
	datum = ipmapremove(routes, key, keylen);
	assert(datum == route);
	tunnel = route->tunnel;
	assert(tunnel != NULL);
	unlinkroute(tunnel, route);
	rmroute(route, routetable_create);
	collapse(tunnel);
}

void
collapse(Tunnel *tunnel)
{
	if (tunnel == NULL)
		return;
	assert(tunnel->nref >= 0);
	if (tunnel->nref == 0) {
		void *datum = ipmapremove(tunnels, tunnel->outer_remote,
		    CIDR_HOST);
		assert(datum == tunnel);
		info("Tearing down tunnel interface %s", tunnel->ifname);
		downtunnel(tunnel);
		bitclr(interfaces, tunnel->ifnum);
		free(tunnel);
	}
}

void
usage(const char *restrict prog)
{
	fprintf(stderr,
	    "Usage: %s [ -d ] [ -T <create_rtable> ] [ -I <ignorespec> ] "
	        "[ -A <acceptspec> ] [ -s <static_ifnum> ] [ -f <testfile> ] "
	        "[ -B <bind_rtable> ] <local-outer-ip> <local-ampr-ip>\n",
	    prog);
	exit(EXIT_FAILURE);
}
