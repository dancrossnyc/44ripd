#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include "dat.h"
#include "fns.h"

uint32_t
readnet32(const octet data[static 4])
{
	return data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3];
}

uint16_t
readnet16(const octet data[static 2])
{
	return data[0] << 8 | data[1];
}

/*
 * If 'netmask' is a valid IPv4 network mask, then '(1 + ~netmask)' will
 * be a power of two.  If 'p' is a power of two, then 'p & (p - 1)' will
 * be zero.  If 'p' is '~netmask + 1' then 'p - 1' is simply '~netmask'.
 */
bool
isvalidnetmask(uint32_t netmask)
{
	return ((~netmask + 1) & ~netmask) == 0;
}

unsigned int
netmask2cidr(uint32_t netmask)
{
	int cidr = 32;

	if (!isvalidnetmask(netmask)) return -1;
	while (cidr > 0 && (netmask & 0x01) == 0) {
		netmask >>= 1;
		cidr--;
	}

	return cidr;
}

uint32_t
cidr2netmask(unsigned int cidr)
{
	if (cidr == 0)
		return 0;
	if (cidr > 32)
		return ~0U;

	return ~0U << (32 - cidr);
}

/*
 * Reverse the bits of an unsigned 32-bit integer.  See Hacker's
 * Delight, second edition, for more details.
 */
uint32_t
revbits(uint32_t w)
{
	w = (w & 0x55555555) << 1 | ((w >> 1) & 0x55555555);
	w = (w & 0x33333333) << 2 | ((w >> 2) & 0x33333333);
	w = (w & 0x0F0F0F0F) << 4 | ((w >> 4) & 0x0F0F0F0F);
	w = w << 24 | (w & 0xFF00) << 8 | ((w >> 8) & 0xFF00) | w >> 24;
	return w;
}

void *
ipmapnearest(IPMap *map, uint32_t key, size_t keylen)
{
	uint32_t rkey = revbits(key);
	IPMap *parent = NULL;

	while (map != NULL && map->keylen <= keylen) {
		uint32_t rkeymask = (1 << map->keylen) - 1;
		uint32_t rkeyfrag = rkey & rkeymask;
		if (map->key != rkeyfrag)
			break;
		rkey >>= map->keylen;
		keylen -= map->keylen;
		if (map->datum != NULL)
			parent = map;
		if (keylen == 0)
			break;
		map = (rkey & 0x01) ? map->right : map->left;
	}
	if (parent == NULL)
		return NULL;

	return parent->datum;
}

void *
ipmapfind(IPMap *map, uint32_t key, size_t keylen)
{
	uint32_t rkey = revbits(key);

	while (map != NULL && map->keylen <= keylen) {
		uint32_t rkeymask = (1 << map->keylen) - 1;
		uint32_t rkeyfrag = rkey & rkeymask;
		if (map->key != rkeyfrag)
			break;
		rkey >>= map->keylen;
		keylen -= map->keylen;
		if (keylen == 0)
			return map->datum;
		map = (rkey & 0x01) ? map->right : map->left;
	}

	return NULL;
}

static IPMap *
mknode(uint32_t key, size_t keylen, void *datum)
{
	IPMap *newnode;

	newnode = calloc(1, sizeof(*newnode));
	if (newnode == NULL)
		fatal("malloc failed");
	newnode->key = key;
	newnode->keylen = keylen;
	newnode->datum = datum;
	newnode->left = NULL;
	newnode->right = NULL;

	return newnode;
}

// Return the number of common low-order bits in 'a' and 'b'.
static size_t
cprefix(size_t n, uint32_t a, uint32_t b)
{
	size_t bits;

	bits = 0;
	while (n-- > 0 && (a & 0x01) == (b & 0x01)) {
		a >>= 1;
		b >>= 1;
		bits++;
	}

	return bits;
}

static inline size_t
nmin(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

IPMap *
mkipmap(void)
{
	return mknode(0, 0, NULL);
}

void
freeipmap(IPMap *map, void (*freedatum)(void *datum))
{
	if (map == NULL) return;
	freeipmap(map->left, freedatum);
	freeipmap(map->right, freedatum);
	if (map->datum != NULL)
		freedatum(map->datum);
	free(map);
}

void *
ipmapinsert(IPMap *root, uint32_t key, size_t keylen, void *datum)
{
	IPMap *map;
	uint32_t rkey = revbits(key);		// Reverse key bits.

	map = root;
	while (map != NULL) {
		IPMap *node = NULL, *newchild = NULL;
		size_t nkcp = 0;		// Common prefix bits.

		if (keylen == map->keylen && rkey == map->key) {
			if (map->datum == NULL)
				map->datum = datum;
			return map->datum;
                }
		nkcp = cprefix(nmin(keylen, map->keylen), rkey, map->key);
		if (nkcp == 0 || nkcp == map->keylen) {
			assert(nkcp < keylen);
			rkey >>= nkcp;
			keylen -= nkcp;
			node = ((rkey & 0x01) == 0) ? map->left : map->right;
			if (node != NULL) {
				map = node;
				continue;
			}
			if ((rkey & 0x01) == 0) {
				assert(map->left == NULL);
				map->left = mknode(rkey, keylen, datum);
			} else {
				assert(map->right == NULL);
				map->right = mknode(rkey, keylen, datum);
			}
			return datum;
		}
		if (nkcp == keylen) {
			uint32_t tkey = map->key >> keylen;
			assert(nkcp < map->keylen);
			node = mknode(tkey, map->keylen - keylen, map->datum);
			node->left = map->left;
			node->right = map->right;
			map->key = rkey;
			map->keylen = keylen;
			map->datum = datum;
			if ((tkey & 0x01) == 0) {
				map->left = node;
				map->right = NULL;
			} else {
				map->left = NULL;
				map->right = node;
			}
			return datum;
		}

		assert(nkcp < map->keylen);
		assert(nkcp < keylen);
		newchild = mknode(map->key >> nkcp,
				  map->keylen - nkcp,
				  map->datum);
		newchild->left = map->left;
		newchild->right = map->right;
		node = mknode(rkey >> nkcp, keylen - nkcp, datum);
		map->key = rkey & ((1 << nkcp) - 1);
		map->keylen = nkcp;
		map->datum = NULL;
		if (newchild->key & 0x01) {
			assert((node->key & 0x01) == 0);
			map->left = node;
			map->right = newchild;
		} else {
			assert((node->key & 0x01) == 1);
			map->left = newchild;
			map->right = node;
		}
		return datum;
        }

	return NULL;
}

void *
ipmapremove(IPMap *root, uint32_t key, size_t akeylen)
{
	IPMap *map, *parent, **pmap;
	uint32_t rkey = revbits(key);		// Reverse key bits.
	size_t keylen = akeylen;
	char pkey[INET_ADDRSTRLEN];

	ipaddrstr(key, pkey);
	pmap = NULL;
	parent = NULL;
	map = root;
	while (map != NULL) {
		size_t nkcp = 0;		// Common prefix bits.

		if (keylen == map->keylen && rkey == map->key) {
			void *datum = map->datum;

			if (map->left != NULL && map->right != NULL) {
				map->datum = NULL;
			} else if (map->left == NULL && map->right == NULL) {
				IPMap *child;

				// If not root, nil our parent's pointer to us.
				if (pmap != NULL)
					*pmap = NULL;
				map->datum = NULL;

				// Don't free the root; it is stable.
				if (map != root)
					free(map);

				// If we are the root, or our parent has data,
				// skip the rest of the logic and return the
				// datum.
				if (parent == NULL || parent->datum != NULL)
					return datum;

				// We nil'ed ourself out of the parent, find
				// the parent's other (possibly-nil) child.
				child = (parent->left != NULL) ?
				            parent->left : parent->right;

				// If it is nil, skip the rest of the logic.
				if (child == NULL)
					return datum;

				// Otherwise, pull the child into the parent:
				// Combine the keys, set datum to the child's
				// datum, and reset the left and right child
				// pointers to the child's.  Finally, free
				// the child node.
				parent->key |= (child->key << parent->keylen);
				parent->keylen += child->keylen;
				parent->datum = child->datum;
				parent->left = child->left;
				parent->right = child->right;
				free(child);
			} else {
				IPMap *child = (map->left != NULL) ?
				                   map->left : map->right;
				assert(child != NULL);
				map->key |= (child->key << map->keylen);
				map->keylen += child->keylen;
				map->datum = child->datum;
				map->left = child->left;
				map->right = child->right;
				free(child);
			}

			return datum;
                }
		nkcp = cprefix(nmin(keylen, map->keylen), rkey, map->key);
		if (nkcp != 0 && nkcp != map->keylen) {
			notice("ipmapremove: divergent key for %s/%zu (nkcp = %zu, keylen = %zu)",
			    pkey, akeylen, nkcp, map->keylen);
			return NULL;
		}
		assert(nkcp < keylen);
		rkey >>= nkcp;
		keylen -= nkcp;
		parent = map;
		if ((rkey & 0x01) == 0) {
			pmap = &map->left;
			map = map->left;
		} else {
			pmap = &map->right;
			map = map->right;
		}
	}
	notice("ipmapremove: key %s/%zu not found", pkey, akeylen);

	return NULL;
}

enum
{
	IPMAP_PREORDER = -1,
	IPMAP_INORDER,
	IPMAP_POSTORDER,
};

static inline int
ipmapdorec(IPMap *map, int order,
    uint32_t key, size_t keylen,
    int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg),
    void *arg)
{
	int r = 0;

	if (map == NULL) return r;
	key |= (map->key << keylen);
	keylen += map->keylen;
	if (order == IPMAP_PREORDER && map->datum != NULL) {
		r = thunk(revbits(key), keylen, map->datum, arg);
		if (r != 0) return r;
	}
	r = ipmapdorec(map->left, order, key, keylen, thunk, arg);
	if (r != 0) return r;
	if (order == IPMAP_INORDER && map->datum != NULL) {
		r = thunk(revbits(key), keylen, map->datum, arg);
		if (r != 0) return r;
	}
	r = ipmapdorec(map->right, order, key, keylen, thunk, arg);
	if (r != 0) return r;
	if (order == IPMAP_POSTORDER && map->datum != NULL)
		r = thunk(revbits(key), keylen, map->datum, arg);

	return r;
}

int
ipmapdo_preorder(IPMap *map,
    int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg),
    void *arg)
{
	return ipmapdorec(map, IPMAP_PREORDER, 0, 0, thunk, arg);
}

int
ipmapdo_inorder(IPMap *map,
    int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg),
    void *arg)
{
	return ipmapdorec(map, IPMAP_INORDER, 0, 0, thunk, arg);
}

int
ipmapdo_postorder(IPMap *map,
    int (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg),
    void *arg)
{
	return ipmapdorec(map, IPMAP_POSTORDER, 0, 0, thunk, arg);
}

typedef struct TrampArg TrampArg;
struct TrampArg {
	void (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg);
	void *arg;
};

static int
trampthunk(uint32_t key, size_t keylen, void *datum, void *arg)
{
	TrampArg *tramparg = arg;

	if (tramparg == NULL)
		return -1;
	tramparg->thunk(key, keylen, datum, tramparg->arg);

	return 0;
}

void
ipmapdo(IPMap *map,
    void (*thunk)(uint32_t key, size_t keylen, void *datum, void *arg),
    void *arg)
{
	TrampArg tramparg;

	memset(&tramparg, 0, sizeof tramparg);
	tramparg.thunk = thunk;
	tramparg.arg = arg;

	ipmapdo_inorder(map, trampthunk, &tramparg);
}

Bitvec *
mkbitvec(void)
{
	return calloc(1, sizeof(Bitvec));
}

void
freebitvec(Bitvec *bits)
{
	assert(bits != NULL);
	free(bits->words);
	free(bits);
}

void
bitset(Bitvec *bits, size_t bit)
{
	uint64_t *words;
	size_t word;

	assert(bits != NULL);
	word = bit/64;
	if (word >= bits->nwords) {
		words = recallocarray(bits->words, bits->nwords, word + 1, sizeof(uint64_t));
		if (words == NULL)
			fatal("malloc failed");
		bits->words = words;
		bits->nwords = word + 1;
	}
	bits->words[word] |= (1ULL << (bit%64));
	if (bit == bits->firstclr) {
		const uint64_t noclr = ~0ULL;
		while (word < bits->nwords && bits->words[word] == noclr)
			word++;
		bits->firstclr = word*64;
	}
}

void
bitclr(Bitvec *bits, size_t bit)
{
	size_t word;

	assert(bits != NULL);
	word = bit/64;
	if (word >= bits->nwords)
		return;
	bits->words[word] &= ~(1ULL << (bit%64));
	if (bit < bits->firstclr)
		bits->firstclr = bit;
}

int
bitget(Bitvec *bits, size_t bit)
{
	size_t word;

	assert(bits != NULL);
	word = bit/64;
	if (word >= bits->nwords)
		return 0;
	return (bits->words[word] >> (bit%64)) & 0x01;
}

size_t
nextbit(Bitvec *bits)
{
	assert(bits != NULL);
	while (bitget(bits, bits->firstclr) == 1)
		++bits->firstclr;
	return bits->firstclr;
}

enum {
	MAX_NUM = (1 << 20),
};

unsigned int
strnum(const char *restrict str)
{
	char *ep;
	unsigned long r;

	ep = NULL;
	r = strtoul(str, &ep, 10);
	if (ep != NULL && *ep != '\0')
		fatal("bad unsigned integer: %s", str);
	if (r > MAX_NUM)
		fatal("integer range error: %s", str);

	return (unsigned int)r;
}

void
initlog(void)
{
	openlog("44ripd", LOG_CONS | LOG_PERROR | LOG_PID, LOG_LOCAL0);
}

void
debug(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_DEBUG, fmt, ap);
	va_end(ap);
}

void
info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_INFO, fmt, ap);
	va_end(ap);
}

void
notice(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_NOTICE, fmt, ap);
	va_end(ap);
}

void
error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
}

void
fatal(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsyslog(LOG_ERR, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}
