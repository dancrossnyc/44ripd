/*
 * A program to manually add or remove tunnel routes.  route(8)
 * is not sufficiently expressive to do this.
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

int
main(int argc, char *argv[])
{
	Route route;
	Tunnel tunnel;
	struct in_addr addr;
	char *slash, *net, *ifname;
	unsigned int cidr;
	uint32_t netmask;
	int ch, rdomain;

	rdomain = 0;
	while ((ch = getopt(argc, argv, "D:?h")) != -1) {
		switch (ch) {
		case 'D':
			rdomain = strnum(optarg);
			break;
		case '?':
		case 'h':
		default:
			fatal("usage: amprroute network/cidr ifname");
			break;
		}
	}
	argc -= optind;
	argv += optind;

	initlog();
	initsys(rdomain);

	if (argc != 2)
		fatal("usage: amprroute network/cidr ifname");
	net = argv[0];
	ifname = argv[1];

	slash = strchr(net, '/');
	if (slash == NULL)
		fatal("network missing CIDR");
	*slash++ = '\0';
	cidr = strnum(slash);
	netmask = cidr2netmask(cidr);

	memset(&addr, 0, sizeof(addr));
	if (inet_pton(AF_INET, net, &addr) <= 0)
		fatal("cannot parse network: %s", net);

	memset(&route, 0, sizeof(route));
	route.subnetmask = netmask;
	route.ipnet = ntohl(addr.s_addr);

	memset(&tunnel, 0, sizeof(tunnel));
	strlcpy(tunnel.ifname, ifname, sizeof(tunnel.ifname));

	addroute(&route, &tunnel, rdomain);

	return 0;
}
