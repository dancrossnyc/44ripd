#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_COMPAT

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

void *
recallocarray(void *p, size_t oelem, size_t nelem, size_t size)
{
	char *np;
	size_t nlen, olen;

	np = reallocarray(p, nelem, size);
	if (np == NULL || nelem <= oelem)
		return np;
	nlen = size*nelem;
	olen = size*oelem;
	memset(np + olen, 0, nlen - olen);

	return np;
}

#endif  // USE_COMPAT
