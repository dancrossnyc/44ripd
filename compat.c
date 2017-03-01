#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef USE_COMPAT

#include "lib.h"

#define SIZE_T_MAX ~(size_t)0
#define SQRT_MAX (1 << (sizeof(size_t)*8/4))

void *
reallocarray(void *p, size_t nelem, size_t size)
{
	if ((nelem >= SQRT_MAX || size >= SQRT_MAX) &&
	    size > 0 && (SIZE_T_MAX/size) < nelem)
	{
		errno = ENOMEM;
		return NULL;
	}
	return realloc(p, nelem*size);
}

#endif  // USE_COMPAT
