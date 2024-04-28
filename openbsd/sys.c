#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dat.h"
#include "fns.h"

static int ctlfd = -1;
static int rtfd = -1;

uint32_t hostmask;

void
initsys(int rtable)
{
	struct in_addr addr;

	ctlfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctlfd < 0)
		fatal("ctl socket: %m");
	rtfd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (rtfd < 0)
		fatal("route socket: %m");
	if (shutdown(rtfd, SHUT_RD) < 0)
		fatal("route shutdown read: %m");
	if (0 && setsockopt(rtfd, SOL_SOCKET, SO_RTABLE, &rtable, sizeof(rtable)) < 0)
		fatal("setsockopt rtfd SO_RTABLE: %m");

	// Create prototype tunnel netmask.
	memset(&addr, 0, sizeof(addr));
	inet_pton(AF_INET, "255.255.255.255", &addr);
	hostmask = addr.s_addr;
}

int
initsock(const char *restrict iface, const char *restrict group, int port, int rtable)
{
	int sd, on;
	uint32_t ifaddr;
	struct sockaddr_in sin;
	struct ip_mreq mr;

	ifaddr = htonl(INADDR_ANY);
	if (strcmp(iface, "*") != 0) {
		struct in_addr addr;
		memset(&addr, 0, sizeof(addr));
		if (inet_pton(AF_INET, iface, &addr) < 0)
			fatal("bad interface address: %m");
		ifaddr = addr.s_addr;
	}

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		fatal("socket: %m");
	on = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		fatal("setsockopt SO_REUSEADDR: %m");
	// On OpenBSD, we use the `route` command to set the listening rtable.
	if (0 && setsockopt(sd, SOL_SOCKET, SO_RTABLE, &rtable, sizeof(rtable)) < 0)
		fatal("setsockopt SO_RTABLE: %m");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = ifaddr;
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		fatal("bind: %m");
	memset(&mr, 0, sizeof(mr));
	inet_pton(AF_INET, group, &mr.imr_multiaddr.s_addr);
	mr.imr_interface.s_addr = ifaddr;
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
		fatal("setsockopt IP_ADD_MEMBERSHIP: %m");

	return sd;
}

/*
 * Bring a tunnel up in routing domain `rdomain`, with
 * the tunnel endpoints routing in `tunneldomain`.
 *
 * Note that the ordering of steps matters here.
 * In particular, we cannot configure IP until we
 * have marked the tunnel up and running.
 *
 * The steps to fully configure a new tunnel are,
 * in order:
 *
 * 1. Create the interface.
 * 2. Configure the tunnel interface.
 * 3. Set the tunnel routing domain.
 * 4. Set the interface routing domain.
 * 5. Configure the interface up and mark it running.
 * 6. Configure IP on the interface.
 */
int
uptunnel(Tunnel *tunnel, int rdomain, int tunneldomain, uint32_t endpoint)
{
	struct ifreq ifr;
	struct if_laddrreq tr;
	struct ifaliasreq ir;
	struct sockaddr_in addr;

	assert(tunnel != NULL);
	assert(ctlfd >= 0);

	// Zero everything.
	memset(&ifr, 0, sizeof(ifr));
	memset(&tr, 0, sizeof(tr));
	memset(&ir, 0, sizeof(ir));
	memset(&addr, 0, sizeof(addr));

	// Create the interface.
	strlcpy(ifr.ifr_name, tunnel->ifname, sizeof(ifr.ifr_name));
	if (ioctl(ctlfd, SIOCIFCREATE, &ifr) < 0)
		fatal("create %s failed: %m", tunnel->ifname);

	// Initialize the tunnel.
	strlcpy(tr.iflr_name, tunnel->ifname, sizeof(tr.iflr_name));

	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(tunnel->local);
	assert(sizeof(addr) <= sizeof(tr.addr));
	memmove(&tr.addr, &addr, sizeof(addr));

	addr.sin_addr.s_addr = htonl(tunnel->remote);
	assert(sizeof(addr) <= sizeof(tr.dstaddr));
	memmove(&tr.dstaddr, &addr, sizeof(addr));

	// Configure the tunnel.
	if (ioctl(ctlfd, SIOCSLIFPHYADDR, &tr) < 0) {
		char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
		ipaddrstr(htonl(tunnel->local), local);
		ipaddrstr(htonl(tunnel->remote), remote);
		fatal("tunnel %s failed (local %s remote %s): %m",
		    tunnel->ifname, local, remote);
	}

	// Set the tunnnel routing domain.
	ifr.ifr_rdomainid = tunneldomain;
	if (ioctl(ctlfd, SIOCSLIFPHYRTABLE, &ifr) < 0)
		fatal("cannot set tunnel routing table %s: %m",
		    tunnel->ifname);

	// Set the interface routing domain.
	ifr.ifr_rdomainid = rdomain;
	if (ioctl(ctlfd, SIOCSIFRDOMAIN, &ifr) < 0)
		fatal("cannot set interface routing table %s: %m",
		    tunnel->ifname);

	// Bring the interface up and mark running.
	//
	// Note that we cannot manually set multicast flags (e.g.
	// IFF_ALLMULTI|IFF_MULTICAST) as the kernel does not allow
	// userspace programs to modify those flags.
	if (ioctl(ctlfd, SIOCGIFFLAGS, &ifr) < 0)
		fatal("cannot get flags for %s: %m", tunnel->ifname);
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	if (ioctl(ctlfd, SIOCSIFFLAGS, &ifr) < 0)
		fatal("cannot set flags for %s: %m", tunnel->ifname);

	// Configure IP on the interface.  Ideally, this wouldn't be
	// necessary, but the default source address and source addresses
	// for ICMP errors are taken from the source side.  So we configure
	// that with the local 44net address and the remote end with 0 as
	// a dummy.
	strlcpy(ir.ifra_name, tunnel->ifname, sizeof(ir.ifra_name));
	addr.sin_addr.s_addr = htonl(endpoint);
	memmove(&ir.ifra_addr, &addr, sizeof(addr));
	addr.sin_addr.s_addr = htonl(0xFFFFFFFF);
	memmove(&ir.ifra_mask, &addr, sizeof(addr));
	if (ioctl(ctlfd, SIOCAIFADDR, &ir) < 0)
		fatal("dummy inet %s failed: %m", tunnel->ifname);

	return 0;
}

int
downtunnel(Tunnel *tunnel)
{
	struct ifreq ifr;

	assert(tunnel != NULL);
	assert(ctlfd >= 0);
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, tunnel->ifname, sizeof(ifr.ifr_name));
	if (ioctl(ctlfd, SIOCIFDESTROY, &ifr) < 0)
		fatal("destroying %s failed: %m", tunnel->ifname);

	return 0;
}

typedef struct Routemsg Routemsg;
struct Routemsg {
	alignas(long) struct rt_msghdr header;
	alignas(long) struct sockaddr_in dst;
	alignas(long) struct sockaddr_dl gw;
	alignas(long) struct sockaddr_in netmask;
};

static size_t
mkrtmsg(int cmd, Route *route, Tunnel *tunnel, int rtable, Routemsg *msg)
{
	static int seqno = 0;
	struct rt_msghdr *header;
	struct sockaddr_in *dst, *netmask;
	struct sockaddr_dl *gw;

	assert(route != NULL);
	assert(rtable >= 0);
	assert(msg != NULL);

	memset(msg, 0, sizeof(*msg));
	header = &msg->header;
	header->rtm_msglen = sizeof(*msg);
	header->rtm_version = RTM_VERSION;
	header->rtm_type = cmd;
	header->rtm_hdrlen = sizeof(*header);
	header->rtm_tableid = rtable;
	header->rtm_addrs = RTA_DST | RTA_NETMASK;
	if (cmd != RTM_DELETE)
		header->rtm_addrs |= RTA_GATEWAY;
	header->rtm_flags = RTF_UP | RTF_CLONING /* | RTF_LLINFO | RTF_CONNECTED*/;
	header->rtm_fmask = 0;
	header->rtm_pid = getpid();
	header->rtm_seq = seqno++;
	if (seqno == INT_MAX)
		seqno = 0;

	dst = &msg->dst;
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;
	dst->sin_addr.s_addr = htonl(route->ipnet);

	// XXX: copy this into a manually aligned byte buffer.
	// This is surely undefined behavior.
	netmask = (struct sockaddr_in *)&msg->gw;
	if (cmd != RTM_DELETE) {
		netmask = &msg->netmask;
		gw = &msg->gw;
		gw->sdl_len = sizeof(*gw);
		gw->sdl_family = AF_LINK;
		gw->sdl_index = if_nametoindex(tunnel->ifname);
	}

	netmask->sin_len = sizeof(*netmask);
	netmask->sin_family = AF_INET;
	netmask->sin_addr.s_addr = htonl(route->subnetmask);

	if (cmd == RTM_DELETE)
		header->rtm_msglen -= sizeof(*gw);

	if (route->subnetmask == hostmask)
		header->rtm_flags |= RTF_HOST; 

	return header->rtm_msglen;
}

int
addroute(Route *route, Tunnel *tunnel, int rtable)
{
	Routemsg rtmsg;
	size_t len;

	len = mkrtmsg(RTM_ADD, route, tunnel, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len) {
		char proute[128];
		routestr(route, tunnel, proute, sizeof(proute));
		error("route add failure (%s): %m", proute);
	}

	return 0;
}

int
chroute(Route *route, Tunnel *tunnel, int rtable)
{
	Routemsg rtmsg;
	size_t len;

	len = mkrtmsg(RTM_CHANGE, route, tunnel, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len) {
		if (errno == ESRCH) {
			rmroute(route, rtable);
			return addroute(route, tunnel, rtable);
		}
		char proute[128];
		routestr(route, tunnel, proute, sizeof(proute));
		error("route change failure (%s): %m", proute);
	}

	return 0;
}

int
rmroute(Route *route, int rtable)
{
	Routemsg rtmsg;
	size_t len;

	len = mkrtmsg(RTM_DELETE, route, NULL, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len)
		if (errno != ESRCH) {
			char proute[128];
			routestr(route, NULL, proute, sizeof(proute));
			error("route remove failure (%s): %m", proute);
		}

	return 0;
}

void
ipaddrstr(uint32_t addr, char buf[static INET_ADDRSTRLEN])
{
	addr = htonl(addr);
	inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
}

void
routestr(Route *route, Tunnel *tunnel, char *buf, size_t size)
{
	char gw[INET_ADDRSTRLEN], proute[INET_ADDRSTRLEN];
	size_t cidr;

	assert(route != NULL);
	cidr = netmask2cidr(ntohl(route->subnetmask));
	ipaddrstr(ntohl(route->ipnet), proute);
	ipaddrstr(ntohl(route->gateway), gw);

	assert(buf != NULL);
	snprintf(buf, size, "%s/%zu -> %s", proute, cidr, gw);
	if (tunnel != NULL) {
		assert(tunnel->ifname != NULL);
		strlcat(buf, " on ", size);
		strlcat(buf, tunnel->ifname, size);
	}
}
