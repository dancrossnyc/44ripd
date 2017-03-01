#include <sys/types.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "dat.h"
#include "lib.h"

void
test(char *snetmask, int expected)
{
	if (netmask2cidr(ntohl(inet_addr(snetmask))) != expected) {
		printf("netmask2cidr(\"%s\") != %d\n", snetmask, expected);
	}
}

int
main(void)
{
	// Test all valid netmasks explicitly.
	test("255.255.255.255", 32);
	test("255.255.255.254", 31);
	test("255.255.255.252", 30);
	test("255.255.255.248", 29);
	test("255.255.255.240", 28);
	test("255.255.255.224", 27);
	test("255.255.255.192", 26);
	test("255.255.255.128", 25);
	test("255.255.255.0", 24);
	test("255.255.254.0", 23);
	test("255.255.252.0", 22);
	test("255.255.248.0", 21);
	test("255.255.240.0", 20);
	test("255.255.224.0", 19);
	test("255.255.192.0", 18);
	test("255.255.128.0", 17);
	test("255.255.0.0", 16);
	test("255.254.0.0", 15);
	test("255.252.0.0", 14);
	test("255.248.0.0", 13);
	test("255.240.0.0", 12);
	test("255.224.0.0", 11);
	test("255.192.0.0", 10);
	test("255.128.0.0", 9);
	test("255.0.0.0", 8);
	test("254.0.0.0", 7);
	test("252.0.0.0", 6);
	test("248.0.0.0", 5);
	test("240.0.0.0", 4);
	test("224.0.0.0", 3);
	test("192.0.0.0", 2);
	test("128.0.0.0", 1);
	test("0.0.0.0", 0);

	return 0;
}
