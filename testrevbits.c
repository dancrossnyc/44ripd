#include <stddef.h>
#include <stdio.h>

#include "dat.h"
#include "fns.h"

void
test(uint32_t w, uint32_t expected)
{
	if (revbits(w) != expected) {
		printf("revbits(%08x) != %08x: %08x\n", w, expected, revbits(w));
	}
}

int
main(void)
{
	test(0xF0000000, 0x0000000F);
	test(0xFF000000, 0x000000FF);
	test(0xF00FF00F, 0xF00FF00F);
	test(0xDEADBEEF, 0xF77DB57B);

	return 0;
}
