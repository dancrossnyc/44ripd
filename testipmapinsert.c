#include <sys/types.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "dat.h"
#include "fns.h"
#include "testfns.h"

typedef struct Entry Entry;
struct Entry {
	Entry *next;
	uint32_t key;
	size_t keylen;
	void *datum;
};

static void
rdumptree(IPMap *map, int i)
{
	char kb[33];

        if (map == NULL) return;
	u32tobin(map->key, map->keylen, kb);
	printf("%-*sKey: %s/%zd Datum: %s\n", i, "",
	    kb, map->keylen, (char *)map->datum);
	if (map->left != NULL) {
		printf("%-*sLeft:\n", i, "");
		rdumptree(map->left, i + 1);
	}
	if (map->right != NULL) {
		printf("%-*sRight:\n", i, "");
		rdumptree(map->right, i + 1);
	}
}

void
dumptree(IPMap *root)
{
	assert(root->datum == NULL);
	assert(root->key == 0U);
	assert(root->keylen == 0ULL);
	printf("Root (no key)\n");
	if (root->left) {
		printf("Left:\n");
		rdumptree(root->left, 1);
	}
	if (root->right) {
		printf("Right:\n");
		rdumptree(root->right, 1);
	}
}

int
main(void)
{
	IPMap *root;
	Entry *entries, *entry, *prev;
	void *v, *datum;
	size_t keylen;
	uint32_t key;
	int c;
	char buf[256], kb[33];

	c = 0;
	entries = NULL;
	root = mkipmap();
	assert(root != NULL);
	while (fgets(buf, sizeof buf, stdin) != NULL) {
		char *bp = buf;
		char *ip = strsep(&bp, " \t\r\n");
		char *subnetmask = strsep(&bp, " \t\r\n");
		assert(ip != NULL);
		assert(subnetmask != NULL);
		key = mkkey(ip);
		keylen = mkkeylen(subnetmask);
		snprintf(buf, sizeof buf, "%d", ++c);
		datum = strdup(buf);
		assert(datum != NULL);
		ipmapinsert(root, key, keylen, datum);
		v = ipmapfind(root, key, keylen);
		if (v != datum) {
			u32tobin(revbits(key), keylen, kb);
			printf("entry %d.%d.%d.%d/%zd %s = %s expected %s\n",
			    (key >> 24) & 0xFF, (key >> 16) & 0xFF,
			    (key >> 8) & 0xFF, key & 0xFF, keylen,
			    kb, (v == NULL) ? "NULL" : (char *)v,
			    (datum == NULL) ? "NULL" : (char *)datum);
			dumptree(root);
			exit(EXIT_FAILURE);
		}
		entry = calloc(1, sizeof(*entry));
		assert(entry != NULL);
		entry->key = key;
		entry->keylen = keylen;
		entry->datum = datum;
		entry->next = entries;
		entries = entry;
	}

	for (entry = entries; entry != NULL; entry = entry->next) {
		v = ipmapfind(root, entry->key, entry->keylen);
		datum = entry->datum;
		if (v != datum) {
			key = entry->key;
			u32tobin(revbits(key), entry->keylen, kb);
			printf("entry %d.%d.%d.%d/%zd %s = %s expected %s\n",
			    (key >> 24) & 0xFF, (key >> 16) & 0xFF,
			    (key >> 8) & 0xFF, key & 0xFF, entry->keylen,
			    kb, (v == NULL) ? "NULL" : (char *)v,
			    (datum == NULL) ? "NULL" : (char *)datum);
			dumptree(root);
			exit(EXIT_FAILURE);
		}
	}

	prev = NULL;
	entry = entries;
	while (entry != NULL) {
		Entry *current = entry;
		entry = entry->next;
		current->next = prev;
		prev = current;
	}
	entries = prev;
	entry = entries;
	while (entry != NULL) {
		Entry *tmp = entry;
		datum = entry->datum;
		v = ipmapremove(root, entry->key, entry->keylen);
		if (v != datum) {
			key = entry->key;
			u32tobin(revbits(key), entry->keylen, kb);
			printf("entry %d.%d.%d.%d/%zd %s = %s expected %s\n",
			    (key >> 24) & 0xFF, (key >> 16) & 0xFF,
			    (key >> 8) & 0xFF, key & 0xFF, entry->keylen,
			    kb, (v == NULL) ? "NULL" : (char *)v,
			    (datum == NULL) ? "NULL" : (char *)datum);
			dumptree(root);
			exit(EXIT_FAILURE);
		}
		entry = entry->next;
		free(datum);
		free(tmp);
		for (tmp = entry; tmp != NULL; tmp = tmp->next) {
			v = ipmapfind(root, tmp->key, tmp->keylen);
			datum = tmp->datum;
			if (v != datum) {
				key = tmp->key;
				u32tobin(revbits(key), tmp->keylen, kb);
				printf("entry %d.%d.%d.%d/%zd %s = %s "
				    "expected %s\n",
				    (key >> 24) & 0xFF, (key >> 16) & 0xFF,
				    (key >> 8) & 0xFF, key & 0xFF,
				    tmp->keylen,
				    kb, (v == NULL) ? "NULL" : (char *)v,
				    (datum == NULL) ? "NULL" : (char *)datum);
				dumptree(root);
				exit(EXIT_FAILURE);
			}
		}
	}
	freeipmap(root, free);

	return 0;
}
