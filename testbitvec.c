#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "dat.h"
#include "fns.h"

int
main(void)
{
	Bitvec *bv = mkbitvec();

	for (int k = 0; k < 65; k++) {
		size_t bit = nextbit(bv);
		if (bit != k) {
			fprintf(stderr, "bit != k: %zu, %d\n", bit, k);
			exit(EXIT_FAILURE);
		}
		assert(bitget(bv, k) == 0);
		bitset(bv, bit);
		assert(bitget(bv, k) == 1);
	}
	assert(bitget(bv, 1024) == 0);

	freebitvec(bv);

	return 0;
}
