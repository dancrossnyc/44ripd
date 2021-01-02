#include <sys/types.h>
#include <arpa/inet.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "dat.h"
#include "fns.h"
#include "testfns.h"

IPMap root, rroot, a, b, c, d, e;
const char *rv = "root";
const char *av = "a";
const char *bv = "b";
const char *cv = "c";
const char *dv = "d";
const char *ev = "e";

void
setup(void)
{
	memset(&root, 0, sizeof(root));
	memset(&rroot, 0, sizeof(rroot));
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	memset(&c, 0, sizeof(c));
	memset(&d, 0, sizeof(d));

	root.key = 0;
	root.keylen = 0;
	root.datum = NULL;
	root.left = &rroot;
	root.right = NULL;

	rroot.key = revbits(mkkey("44.0.0.0"));
	rroot.keylen = 8;
	rroot.datum = (void *)rv;
	rroot.left = &a;
	rroot.right = &b;

	a.key = (revbits(mkkey("44.0.0.1")) >> 8);
	a.keylen = 24;
	a.datum = (void *)av;
	a.left = NULL;
	a.right = NULL;

	b.key = (revbits(mkkey("44.130.0.0")) >> 8);
	b.keylen = 8;
	b.datum = (void *)bv;
	b.left = &c;
	b.right = &d;

	c.key = (revbits(mkkey("44.130.24.0")) >> 16);
	c.keylen = 8;
	c.datum = (void *)cv;
	c.left = &e;
	c.right = NULL;

	d.key = (revbits(mkkey("44.130.130.0")) >> 16);
	d.keylen = 8;
	d.datum = (void *)dv;
	d.left = NULL;
	d.right = NULL;

	e.key = (revbits(mkkey("44.130.24.25")) >> 24);
	e.keylen = 8;
	e.datum = (void *)ev;
	e.left = NULL;
	e.right = NULL;
}

void
test(const char *key, size_t keylen, const char *expected)
{
	void *v = ipmapnearest(&root, mkkey(key), keylen);
	if (v != expected) {
		const char *exp = expected ? expected : "NULL";
		printf("ipmapnearest(&root, \"%s\", %zu) != %s (%p -> %s)\n",
		       key, keylen, exp, v, (v == NULL) ? "NULL" : (char *)v);
	}
}

int
main(void)
{
	setup();

	test("130.0.0.1", 32, NULL);
	test("44.0.0.1", 24, rv);
	test("44.0.0.12", 32, rv);
	test("44.0.0.1", 32, av);
	test("44.130.24.25", 32, ev);
	test("44.130.24.1", 32, cv);
	test("44.188.0.1", 32, rv);
	test("44.130.130.0", 24, dv);
	test("44.130.130.0", 27, dv);
	test("44.130.131.0", 27, bv);
	test("44.130.24.0", 24, cv);

	return 0;
}
