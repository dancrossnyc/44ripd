#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <limits.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dat.h"
#include "lib.h"
#include "log.h"
#include "sys.h"

static int ctlfd = -1;
static int rtfd = -1;
static int rtfd_rtable = -1;

static uint32_t hostmask;

static inline size_t
sa_roundup(size_t len)
{
	size_t residual = len % sizeof(long);
	if (residual != 0)
		len += sizeof(long) - residual;
	return len;
}

void
discoverifs(int rtable, if_discovered_thunk thunk, void *arg)
{
	struct ifaddrs *ifa;
	int tmpctlfd;

	tmpctlfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (tmpctlfd < 0)
		fatale("ctl socket");

	if (getifaddrs(&ifa) != 0)
		fatale("getifaddrs");

	for (; ifa != NULL; ifa = ifa->ifa_next) {
		struct ifreq ifr;
		int gifnum;
		uint32_t outer_local, outer_remote;

		if ((ifa->ifa_flags & IFF_UP) == 0)
			continue;
		if (sscanf(ifa->ifa_name, "gif%d", &gifnum) != 1)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (ifa->ifa_dstaddr->sa_family != AF_INET)
			continue;
		strlcpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
		if (ioctl(tmpctlfd, SIOCGIFPSRCADDR, &ifr) < 0)
			fatal("get %s outer src addr: %m", ifa->ifa_name);
		if (ifr.ifr_addr.sa_family != AF_INET)
			continue;
		outer_local = ntohl(
		    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
		if (ioctl(tmpctlfd, SIOCGIFPDSTADDR, &ifr) < 0)
			fatal("get %s outer dst addr: %m", ifa->ifa_name);
		if (ifr.ifr_addr.sa_family != AF_INET)
			continue;
		outer_remote = ntohl(
		    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
		if (ioctl(tmpctlfd, SIOCGIFFIB, &ifr) < 0)
			fatal("get %s fib: %m", ifa->ifa_name);
		if (ifr.ifr_fib != rtable)
			continue;
		uint32_t inner_local = ntohl(
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
		);
		uint32_t inner_remote = ntohl(
		    ((struct sockaddr_in *)ifa->ifa_dstaddr)->sin_addr.s_addr
		);

		thunk(ifa->ifa_name, gifnum, outer_local, outer_remote,
		    inner_local, inner_remote, arg);
	}

	freeifaddrs(ifa);
	close(tmpctlfd);
}

void
discoverrts(int rtable, rt_discovered_thunk thunk, void *arg)
{
	int mib[7];
	const size_t mib_depth = sizeof(mib) / sizeof(mib[0]);

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;
	mib[6] = rtable;

	size_t rtbufsize;

	if (sysctl(mib, mib_depth, NULL, &rtbufsize, NULL, 0) < 0)
		fatale("sysctl: net.route sizing");
	
	char *rtbuf = malloc(rtbufsize);
	if (rtbuf == NULL)
		fatal("malloc net.route sysctl");

	if (sysctl(mib, mib_depth, rtbuf, &rtbufsize, NULL, 0) < 0)
		fatale("sysctl: net.route");

	char *hdr;
	struct rt_msghdr *rtm;

	for (hdr = rtbuf; hdr < rtbuf + rtbufsize; hdr += rtm->rtm_msglen) {
		char ifname[MAX_TUN_IFNAME];
		uint32_t net, netmask, dest;
		int isaddr;

		rtm = (struct rt_msghdr *) hdr;
		if (rtm->rtm_version != RTM_VERSION)
			fatal("Route socket version mismatch");
		if (((~rtm->rtm_addrs) & (RTA_DST|RTA_NETMASK|RTA_GATEWAY))!=0)
			continue;
		struct sockaddr *netaddr = (struct sockaddr *)(rtm + 1);
		if (netaddr->sa_family != AF_INET)
			continue;
		struct sockaddr_in *sin = (struct sockaddr_in *)netaddr;
		net = ntohl(sin->sin_addr.s_addr);
		struct sockaddr *gwaddr = (struct sockaddr *)
		    (((char *)netaddr) + sa_roundup(netaddr->sa_len));
		if (gwaddr->sa_family == AF_LINK) {
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)gwaddr;
			if (sdl->sdl_nlen == 0)
				// Nondescript "link" route. Not needed.
				continue;
			isaddr = 0;
			dest = 0;
			if (sdl->sdl_nlen > sizeof(ifname)-1)
				fatal("interface name too big");
			memcpy(ifname, sdl->sdl_data, sdl->sdl_nlen);
			ifname[sdl->sdl_nlen] = '\0';
		} else if (gwaddr->sa_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)gwaddr;
			isaddr = 1;
			dest = ntohl(sin->sin_addr.s_addr);
		} else {
			// Unknown gateway address family.
			continue;
		}
		struct sockaddr *maskaddr = (struct sockaddr *)
		    (((char *)gwaddr) + sa_roundup(gwaddr->sa_len));
		if (maskaddr->sa_len == 0) {
			netmask = 0;
		} else {
			sin = (struct sockaddr_in *)maskaddr;
			netmask = ntohl(sin->sin_addr.s_addr);
		}

		thunk(net, netmask, isaddr, dest, ifname, arg);
	}

	free(rtbuf);
}

void
initsys(int rtable)
{
	struct in_addr addr;

	ctlfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctlfd < 0)
		fatale("ctl socket");
	rtfd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (rtfd < 0)
		fatale("route socket");
	if (shutdown(rtfd, SHUT_RD) < 0)
		fatale("route shutdown read");

	//
	// FreeBSD doesn't have the ability to specify which route table
	// to modify on a routing-command basis. It only allows it to be
	// set on the routing socket itself for the entire session.
	//
	// Fortunately this is not a problem as we don't switch the routing
	// table we use on a command-to-command basis anyways.
	//
	if (setsockopt(rtfd, SOL_SOCKET, SO_SETFIB, &rtable,
	               sizeof(rtable)) < 0)
		fatale("setsockopt rtfd SO_SETFIB");

	//
	// Save the route table that we set so that we can check that
	// all incoming route table modification requests are meant
	// for said table. (This is merely to check the program for
	// bitrot).
	//
	rtfd_rtable = rtable;

	// Create prototype tunnel netmask.
	memset(&addr, 0, sizeof(addr));
	inet_pton(AF_INET, "255.255.255.255", &addr);
	hostmask = addr.s_addr;
}

int
initsock(const char *restrict group, int port, int rtable)
{
	int sd, on;
	struct sockaddr_in sin;
	struct ip_mreq mr;

	sd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		fatale("socket UDP");
	on = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		fatale("setsockopt SO_REUSEADDR");
	if (setsockopt(sd, SOL_SOCKET, SO_SETFIB, &rtable, sizeof(rtable)) < 0)
		fatale("setsockopt SO_SETFIB");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		fatale("bind UDP");
	memset(&mr, 0, sizeof(mr));
	inet_pton(AF_INET, group, &mr.imr_multiaddr.s_addr);
	mr.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
		fatale("setsockopt IP_ADD_MEMBERSHIP");

	return sd;
}

/*
 * Bring a tunnel up, routing against rtable.
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
 * 6. Configure outer IP source and destination on the interface.
 * 7. Configure inner IPs on the interface.
 */
int
uptunnel(Tunnel *tunnel, int rtable)
{
	struct ifreq ifr;
	struct in_aliasreq ifar;
	struct sockaddr_in addr;

	assert(tunnel != NULL);
	assert(ctlfd >= 0);

	// Zero everything.
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifar, 0, sizeof(ifar));
	memset(&addr, 0, sizeof(addr));

#ifndef SIOCSTUNFIB
	//
	// FreeBSD 10.2 introduced the SIOSTUNFIB ioctl, which allows
	// the route table (FIB) used by the tunnel to be changed after the
	// tunnel has been created.
	//
	// Before FreeBSD 10.2, the only way to set this value was to
	// set the FIB on the thread which created the interface.
	// Set the tunnnel routing domain.
	if (setfib(rtable) < 0)
		fatal("cannot set tunnel routing table %s: %m",
		    tunnel->ifname);
#endif

	// Create the interface.
	strlcpy(ifr.ifr_name, tunnel->ifname, sizeof(ifr.ifr_name));
	if (ioctl(ctlfd, SIOCIFCREATE, &ifr) < 0)
		fatal("create %s failed: %m");

#ifndef SIOCSTUNFIB
	// Restore thread's FIB
	setfib(0);
#endif
	
	// Initialize the alias structure.  This is used for both
	// configuring the tunnel and IP.
	strlcpy(ifar.ifra_name, tunnel->ifname, sizeof(ifar.ifra_name));

	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(tunnel->outer_local);
	assert(sizeof(addr) <= sizeof(ifar.ifra_addr));
	memmove(&ifar.ifra_addr, &addr, sizeof(addr));

	addr.sin_addr.s_addr = htonl(tunnel->outer_remote);
	assert(sizeof(addr) <= sizeof(ifar.ifra_dstaddr));
	memmove(&ifar.ifra_dstaddr, &addr, sizeof(addr));

	// Configure the tunnel.
	if (ioctl(ctlfd, SIOCSIFPHYADDR, &ifar) < 0) {
		char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];

		ipaddrstr(tunnel->outer_local, local);
		ipaddrstr(tunnel->outer_remote, remote);
		fatal("tunnel %s failed (local %s remote %s): %m",
		    tunnel->ifname, local, remote);
	}

	ifr.ifr_fib = rtable;

#ifdef SIOCSTUNFIB
	//
	// FreeBSD 10.2 introduced the SIOSTUNFIB ioctl, which allows
	// the route table (FIB) used by the tunnel to be changed after the
	// tunnel has been created.
	//
	// Before FreeBSD 10.2, the only way to set this value was to
	// set the FIB on the thread which created the interface.
	// Set the tunnnel routing domain.
	if (ioctl(ctlfd, SIOCSTUNFIB, &ifr) < 0)
		fatal("cannot set tunnel routing table %s: %m",
		    tunnel->ifname);
#endif
	
	// Set the interface routing domain.
	if (ioctl(ctlfd, SIOCSIFFIB, &ifr) < 0)
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


	//
	// Set up the tunnel's inner addresses.
	//
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(tunnel->inner_local);
	assert(sizeof(addr) <= sizeof(ifar.ifra_addr));
	memmove(&ifar.ifra_addr, &addr, sizeof(addr));

	addr.sin_addr.s_addr = htonl(tunnel->inner_remote);
	assert(sizeof(addr) <= sizeof(ifar.ifra_dstaddr));
	memmove(&ifar.ifra_dstaddr, &addr, sizeof(addr));

	// Configure IP on interface.
	if (ioctl(ctlfd, SIOCAIFADDR, &ifar) < 0) {
		char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
		ipaddrstr(tunnel->inner_local, local);
		ipaddrstr(tunnel->inner_remote, remote);
		fatal("inet %s failed (local %s, remote %s): %m",
		    tunnel->ifname, local, remote);
	}

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
buildrtmsg(int cmd, Route *route, Tunnel *tunnel, int rtable, Routemsg *msg)
{
	static int seqno = 0;
	struct rt_msghdr *header;
	struct sockaddr_in *dst, *netmask;
	struct sockaddr_dl *gw;

	assert(route != NULL);
	if (cmd != RTM_DELETE)
		assert(tunnel != NULL);
	assert(msg != NULL);

	//
	// On FreeBSD we cannot switch the route table being modified from
	// message to message. This code doesn't do so anyways, but make
	// sure of that to insure against bitrot.
	//
	assert(rtable == rtfd_rtable);

	memset(msg, 0, sizeof(*msg));
	header = &msg->header;
	header->rtm_msglen = sizeof(*msg);
	header->rtm_version = RTM_VERSION;
	header->rtm_type = cmd;
	header->rtm_addrs = RTA_DST | RTA_NETMASK;
	if (cmd != RTM_DELETE)
		header->rtm_addrs |= RTA_GATEWAY;
	header->rtm_flags = RTF_UP /* | RTF_STATIC */;
	header->rtm_fmask = 0;
	header->rtm_pid = getpid();
	header->rtm_seq = seqno++;
	if (seqno == INT_MAX)
		seqno = 0;

	dst = &msg->dst;
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;
	dst->sin_addr.s_addr = htonl(route->ipnet);

	if (cmd != RTM_DELETE) {
		gw = &msg->gw;
		gw->sdl_len = sizeof(*gw);
		gw->sdl_family = AF_LINK;
		gw->sdl_nlen = strlen(tunnel->ifname);
		strncpy(gw->sdl_data, tunnel->ifname, sizeof(gw->sdl_data));
		netmask = (struct sockaddr_in *) &msg->netmask;
	} else {
		netmask = (struct sockaddr_in *) &msg->gw;
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

	if (route->subnetmask == hostmask &&
	    route->ipnet == tunnel->inner_remote)
		//
		// There's no need to add this route. It will
		// have automatically been added by the kernel when the
		// tunnel was brought up.
		//
		return 0;

	len = buildrtmsg(RTM_ADD, route, tunnel, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len)
		fatale("route add failure");

	return 0;
}

int
chroute(Route *route, Tunnel *tunnel, int rtable)
{
	Routemsg rtmsg;
	size_t len;

	len = buildrtmsg(RTM_CHANGE, route, tunnel, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len) {
		if (errno == ESRCH) {
			rmroute(route, rtable);
			return addroute(route, tunnel, rtable);
		}
		char net[INET_ADDRSTRLEN], oldgw[INET_ADDRSTRLEN],
		     newgw[INET_ADDRSTRLEN];
		int cidr;
		ipaddrstr(route->ipnet, net);
		cidr = netmask2cidr(route->subnetmask);
		ipaddrstr(route->tunnel->outer_remote, oldgw);
		ipaddrstr(tunnel->outer_remote, newgw);
		fatal("route change failure: net %s/%d -> %s:%s to "
		    "%s:%s: %m", net, cidr, route->tunnel->ifname,
		    oldgw, tunnel->ifname, newgw);
	}

	return 0;
}

int
rmroute(Route *route, int rtable)
{
	Routemsg rtmsg;
	size_t len;

	len = buildrtmsg(RTM_DELETE, route, NULL, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len)
		if (errno != ESRCH)
			fatale("route change failure");

	return 0;
}

/*
 * Assumes addr is in host order.
 */
void
ipaddrstr(uint32_t addr, char buf[static INET_ADDRSTRLEN])
{
	uint32_t addr_n = htonl(addr);
	inet_ntop(AF_INET, &addr_n, buf, INET_ADDRSTRLEN);
}
