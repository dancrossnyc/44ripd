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
	Tunnel tunnel;
	struct in_addr local, remote;
	int ch, rdomain, tunneldomain;

	rdomain = 0;
	tunneldomain = 0;
	while ((ch = getopt(argc, argv, "D:T:?h")) != -1) {
		switch (ch) {
		case 'T':
			tunneldomain = strnum(optarg);
			break;
		case 'D':
			rdomain = strnum(optarg);
			break;
		case '?':
		case 'h':
		default:
			fatal("usage: uptunnel ifname local remote");
			break;
		}
	}
	argc -= optind;
	argv += optind;

	initlog();
	initsys(rdomain);

	if (argc != 3)
		fatal("usage: uptunnel ifname local remote");

	memset(&local, 0, sizeof(local));
	if (inet_pton(AF_INET, argv[1], &local) <= 0)
		fatal("cannot parse local: %s", argv[1]);

	memset(&remote, 0, sizeof(remote));
	if (inet_pton(AF_INET, argv[2], &remote) <= 0)
		fatal("cannot parse remote: %s", argv[2]);

	memset(&tunnel, 0, sizeof(tunnel));
	strlcpy(tunnel.ifname, argv[0], sizeof(tunnel.ifname));
	tunnel.local = ntohl(local.s_addr);
	tunnel.remote = ntohl(remote.s_addr);

	uptunnel(&tunnel, rdomain, tunneldomain);

	return 0;
}
