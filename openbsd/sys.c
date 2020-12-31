#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
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
		err(EXIT_FAILURE, "ctl socket");
	rtfd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (rtfd < 0)
		err(EXIT_FAILURE, "route socket");
	if (shutdown(rtfd, SHUT_RD) < 0)
		err(EXIT_FAILURE, "route shutdown read");
	//if (setsockopt(rtfd, SOL_SOCKET, SO_RTABLE, &rtable, sizeof(rtable)) < 0)
	//	err(EXIT_FAILURE, "setsockopt rtfd SO_RTABLE");

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
		err(EXIT_FAILURE, "socket");
	on = 1;
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		err(EXIT_FAILURE, "setsockopt SO_REUSEADDR");
	if (setsockopt(sd, SOL_SOCKET, SO_RTABLE, &rtable, sizeof(rtable)) < 0)
		err(EXIT_FAILURE, "setsockopt SO_RTABLE");
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		err(EXIT_FAILURE, "bind");
	memset(&mr, 0, sizeof(mr));
	inet_pton(AF_INET, group, &mr.imr_multiaddr.s_addr);
	mr.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
		err(EXIT_FAILURE, "setsockopt IP_ADD_MEMBERSHIP");

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
 * 6. Configure IP on the interface.
 */
int
uptunnel(Tunnel *tunnel, int rtable)
{
	struct ifreq ifr;
	struct ifaliasreq ifar;
	struct sockaddr_in addr;

	assert(tunnel != NULL);
	assert(ctlfd >= 0);

	// Zero everything.
	memset(&ifr, 0, sizeof(ifr));
	memset(&ifar, 0, sizeof(ifar));
	memset(&addr, 0, sizeof(addr));

	// Create the interface.
	strlcpy(ifr.ifr_name, tunnel->ifname, sizeof(ifr.ifr_name));
	if (ioctl(ctlfd, SIOCIFCREATE, &ifr) < 0)
		err(EXIT_FAILURE, "create %s failed", tunnel->ifname);

	// Initialize the alias structure.  This is used for both
	// configuring the tunnel and IP.
	strlcpy(ifar.ifra_name, tunnel->ifname, sizeof(ifar.ifra_name));

	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(tunnel->local);
	assert(sizeof(addr) <= sizeof(ifar.ifra_addr));
	memmove(&ifar.ifra_addr, &addr, sizeof(addr));

	addr.sin_addr.s_addr = htonl(tunnel->remote);
	assert(sizeof(addr) <= sizeof(ifar.ifra_dstaddr));
	memmove(&ifar.ifra_dstaddr, &addr, sizeof(addr));

	addr.sin_addr.s_addr = htonl(hostmask);
	assert(sizeof(addr) <= sizeof(ifar.ifra_mask));
	memmove(&ifar.ifra_mask, &addr, sizeof(addr));

	// Configure the tunnel.
	if (ioctl(ctlfd, SIOCSLIFPHYADDR, &ifar) < 0) {
		char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &tunnel->local, local, sizeof(local));
		inet_ntop(AF_INET, &tunnel->remote, remote, sizeof(remote));
		err(EXIT_FAILURE, "tunnel %s failed (local %s remote %s)",
		    tunnel->ifname, local, remote);
	}

	// Set the tunnnel routing domain.
	ifr.ifr_rdomainid = rtable;
	if (ioctl(ctlfd, SIOCSLIFPHYRTABLE, &ifr) < 0)
		err(EXIT_FAILURE, "cannot set tunnel routing table %s",
		    tunnel->ifname);

	// Set the interface routing domain.
	if (ioctl(ctlfd, SIOCSIFRDOMAIN, &ifr) < 0)
		err(EXIT_FAILURE, "cannot set interface routing table %s",
		    tunnel->ifname);

	// Bring the interface up and mark running.
	//
	// Note that we cannot manually set multicast flags (e.g.
	// IFF_ALLMULTI|IFF_MULTICAST) as the kernel does not allow
	// userspace programs to modify those flags.
	if (ioctl(ctlfd, SIOCGIFFLAGS, &ifr) < 0)
		err(EXIT_FAILURE, "cannot get flags for %s", tunnel->ifname);
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	if (ioctl(ctlfd, SIOCSIFFLAGS, &ifr) < 0)
		err(EXIT_FAILURE, "cannot set flags for %s", tunnel->ifname);

	// Configure IP on interface.
	if (ioctl(ctlfd, SIOCAIFADDR, &ifar) < 0) {
		char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &tunnel->local, local, sizeof(local));
		inet_ntop(AF_INET, &tunnel->remote, remote, sizeof(remote));
		err(EXIT_FAILURE, "inet %s failed (local %s, remote %s)",
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
		err(EXIT_FAILURE, "destroying %s failed", tunnel->ifname);

	return 0;
}

typedef struct Routemsg Routemsg;
struct Routemsg {
	alignas(long) struct rt_msghdr header;
	alignas(long) struct sockaddr_in dst;
	alignas(long) struct sockaddr_in gw;
	alignas(long) struct sockaddr_in netmask;
};

static size_t
buildrtmsg(int cmd, Route *route, Tunnel *tunnel, int rtable, Routemsg *msg)
{
	static int seqno = 0;
	struct rt_msghdr *header;
	struct sockaddr_in *dst, *gw, *netmask;

	assert(route != NULL);
	if (cmd != RTM_DELETE)
		assert(tunnel != NULL);
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

	netmask = &msg->gw;
	if (cmd != RTM_DELETE) {
		netmask = &msg->netmask;
		gw = &msg->gw;
		gw->sin_len = sizeof(*gw);
		gw->sin_family = AF_INET;
		gw->sin_addr.s_addr = htonl(tunnel->remote);
	}

	netmask->sin_len = sizeof(*netmask);
	netmask->sin_family = AF_INET;
	netmask->sin_addr.s_addr = htonl(route->subnetmask);
	if (cmd == RTM_DELETE)
		header->rtm_msglen -= sizeof(*gw);

	header->rtm_flags |=
	    (route->subnetmask == hostmask) ? RTF_HOST : RTF_GATEWAY;

	return header->rtm_msglen;
}

int
addroute(Route *route, Tunnel *tunnel, int rtable)
{
	Routemsg rtmsg;
	size_t len;

	len = buildrtmsg(RTM_ADD, route, tunnel, rtable, &rtmsg);
	if (write(rtfd, &rtmsg, len) != len)
		err(EXIT_FAILURE, "route add failure");

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
		err(EXIT_FAILURE, "route change failure");
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
			err(EXIT_FAILURE, "route change failure");

	return 0;
}

void
ipaddrstr(uint32_t addr, char buf[static INET_ADDRSTRLEN])
{
	inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
}
