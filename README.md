44ripd: An AMPRNet mesh maintenance daemon for BSD
==================================================

This is 44ripd, a daemon for maintaining routes and tunnels on the
AMPRNet amateur radio IP network (IPv4 network 44/9 and 44.128.0.0/10).

This software implements a listener for RIPv2 packets containing route
and tunnel information for gateways to APMRNet sub-networks as well as
support for maintaining routes and IPENCAP tunnels.  It runs on OpenBSD,
but is likely portable to other BSD variants with fairly little work.
The author current runs it on a Ubiquiti Networks EdgeRouter Lite
running OpenBSD/Octeon.

The software is released under the 2-clause BSD license.

Author
------
44ripd was written by Dan Cross, KZ2X.  Reach me via email at
crossd@gmail.com or find me on the web at http://pub.gajendra.net/

TODO
----
* Write a man page.
* At startup, the daemon should probe the state of the system and
  use the existing routing table and interfaces to bootstrap its
  internal copies.
* Logging and assertions could always be improved.
