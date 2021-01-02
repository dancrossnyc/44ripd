#include <sys/types.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "dat.h"
#include "fns.h"

void
testn2c(const char *snetmask, int expected)
{
	if (netmask2cidr(ntohl(inet_addr(snetmask))) != expected)
		printf("netmask2cidr(\"%s\") != %d\n", snetmask, expected);
}

void
testc2n(int cidr, const char *expected)
{
	if (cidr2netmask(cidr) != ntohl(inet_addr(expected))) {
		printf("cidr2netmask(%d) != \"%s\"\n", cidr, expected);
		printf("cidr2netmask(%d) = %x\n", cidr, cidr2netmask(cidr));
	}
}

int
main(void)
{
	// Test all valid netmasks explicitly.
	testn2c("255.255.255.255", 32);
	testn2c("255.255.255.254", 31);
	testn2c("255.255.255.252", 30);
	testn2c("255.255.255.248", 29);
	testn2c("255.255.255.240", 28);
	testn2c("255.255.255.224", 27);
	testn2c("255.255.255.192", 26);
	testn2c("255.255.255.128", 25);
	testn2c("255.255.255.0", 24);
	testn2c("255.255.254.0", 23);
	testn2c("255.255.252.0", 22);
	testn2c("255.255.248.0", 21);
	testn2c("255.255.240.0", 20);
	testn2c("255.255.224.0", 19);
	testn2c("255.255.192.0", 18);
	testn2c("255.255.128.0", 17);
	testn2c("255.255.0.0", 16);
	testn2c("255.254.0.0", 15);
	testn2c("255.252.0.0", 14);
	testn2c("255.248.0.0", 13);
	testn2c("255.240.0.0", 12);
	testn2c("255.224.0.0", 11);
	testn2c("255.192.0.0", 10);
	testn2c("255.128.0.0", 9);
	testn2c("255.0.0.0", 8);
	testn2c("254.0.0.0", 7);
	testn2c("252.0.0.0", 6);
	testn2c("248.0.0.0", 5);
	testn2c("240.0.0.0", 4);
	testn2c("224.0.0.0", 3);
	testn2c("192.0.0.0", 2);
	testn2c("128.0.0.0", 1);
	testn2c("0.0.0.0", 0);

	testc2n(32, "255.255.255.255");
	testc2n(31, "255.255.255.254");
	testc2n(30, "255.255.255.252");
	testc2n(29, "255.255.255.248");
	testc2n(28, "255.255.255.240");
	testc2n(27, "255.255.255.224");
	testc2n(26, "255.255.255.192");
	testc2n(25, "255.255.255.128");
	testc2n(24, "255.255.255.0");
	testc2n(23, "255.255.254.0");
	testc2n(22, "255.255.252.0");
	testc2n(21, "255.255.248.0");
	testc2n(20, "255.255.240.0");
	testc2n(19, "255.255.224.0");
	testc2n(18, "255.255.192.0");
	testc2n(17, "255.255.128.0");
	testc2n(16, "255.255.0.0");
	testc2n(15, "255.254.0.0");
	testc2n(14, "255.252.0.0");
	testc2n(13, "255.248.0.0");
	testc2n(12, "255.240.0.0");
	testc2n(11, "255.224.0.0");
	testc2n(10, "255.192.0.0");
	testc2n(9, "255.128.0.0");
	testc2n(8, "255.0.0.0");
	testc2n(7, "254.0.0.0");
	testc2n(6, "252.0.0.0");
	testc2n(5, "248.0.0.0");
	testc2n(4, "240.0.0.0");
	testc2n(3, "224.0.0.0");
	testc2n(2, "192.0.0.0");
	testc2n(1, "128.0.0.0");
	testc2n(0, "0.0.0.0");

	return 0;
}
