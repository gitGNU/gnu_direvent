/* This file is part of Direvent.
   Copyright (C) 2012-2016 Sergey Poznyakoff.
 
   Direvent is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
 
   Direvent is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with Direvent.  If not, see <http://www.gnu.org/licenses/>. */

#include "direvent.h"

/* |hash_size| defines a sequence of symbol table sizes. These are prime
   numbers, each of which is approximately twice its predecessor. */

static unsigned int hash_size[] = {
	7, 17, 37, 101, 229, 487, 1009, 2039, 4091, 8191, 16411,
	32831, 65647, 131231, 262469, 524921, 1049849, 2099707
};

/* |max_rehash| keeps the number of entries in |hash_size| table. */
static unsigned int max_rehash = sizeof(hash_size) / sizeof(hash_size[0]);

struct hashtab {
	int flags;
	unsigned int hash_num;  /* Index to hash_size table */
	size_t elsize;          /* Size of an element */
	struct hashent **tab;
	unsigned (*hash_fun)(void *, unsigned long hash_num);
	int (*cmp_fun)(const void *, const void *);
	int (*copy_fun)(void *, void *);
	void *(*hashent_alloc_fun)(size_t size);
	void (*hashent_free_fun) (void *);
};

static void
hashent_free(struct hashtab *st, void *ptr)
{
	if (st->hashent_free_fun)
		st->hashent_free_fun(ptr);
	else
		free(ptr);
}

static struct hashent *
hashent_alloc(struct hashtab *st, void *key)
{
	struct hashent *ent;
	
	ent = st->hashent_alloc_fun ?
		st->hashent_alloc_fun(st->elsize) : malloc(st->elsize);
	if (ent) {
		memset(ent, 0, st->elsize);
		if (st->copy_fun(ent, key)) {
			int ec = errno;
			hashent_free(st, ent);
			errno = ec;
			return NULL;
		}
	}
	return ent;
}


static unsigned
hashtab_insert_pos(struct hashtab *st, void *elt)
{
	unsigned i;
	unsigned pos = st->hash_fun(elt, hash_size[st->hash_num]);
	
	for (i = pos; st->tab[i];) {
		if (++i >= hash_size[st->hash_num])
			i = 0;
		if (i == pos)
			/* FIXME: Error message? */
			abort();
	}
	return i;
}

int
hashtab_replace(struct hashtab *st, void *ent, void **old_ent)
{
	struct hashent *entry;
	unsigned i, pos = st->hash_fun(ent, hash_size[st->hash_num]);
	for (i = pos; entry = st->tab[i];) {
		if (st->cmp_fun(entry, ent) == 0)
			break;
		if (++i >= hash_size[st->hash_num])
			i = 0;
		if (i == pos)
			return ENOENT;
	}
	if (old_ent)
		*old_ent = entry;
	st->tab[i] = ent;
	return 0;
}

static int
hashtab_rehash(struct hashtab *st)
{
	struct hashent **old_tab = st->tab;
	struct hashent **new_tab;
	unsigned int i;
	unsigned int hash_num = st->hash_num + 1;
	
	if (hash_num >= max_rehash)
		return E2BIG;

	new_tab = calloc(hash_size[hash_num], sizeof(*new_tab));
	if (!new_tab)
		return ENOMEM;
	st->tab = new_tab;
	if (old_tab) {
		st->hash_num = hash_num;
		for (i = 0; i < hash_size[hash_num-1]; i++) {
			struct hashent *elt = old_tab[i];
			if (elt->used) {
				unsigned n = hashtab_insert_pos(st, elt);
				new_tab[n] = elt;
			}
		}
		free(old_tab);
	}
	return 0;
}

const char *
hashtab_strerror(int rc)
{
	switch (rc) {
	case ENOENT:
		return _("element not found in table");
	case E2BIG:
		return _("symbol table is full");
	case ENOMEM:
		return _("out of memory");
	}
	return strerror(rc);
}

int
hashtab_remove(struct hashtab *st, void *elt)
{
	unsigned int pos, i, j, r;
	struct hashent *entry;
	
	pos = st->hash_fun(elt, hash_size[st->hash_num]);
	for (i = pos; entry = st->tab[i];) {
		if (st->cmp_fun(entry, elt) == 0)
			break;
		if (++i >= hash_size[st->hash_num])
			i = 0;
		if (i == pos)
			return ENOENT;
	}
	
	hashent_free(st, entry);

	for (;;) {
		st->tab[i] = NULL;
		j = i;

		do {
			if (++i >= hash_size[st->hash_num])
				i = 0;
			if (!st->tab[i])
				return 0;
			r = st->hash_fun(st->tab[i], hash_size[st->hash_num]);
		}
		while ((j < r && r <= i)
		       || (i < j && j < r) || (r <= i && i < j));
		st->tab[j] = st->tab[i];
	}
	return 0;
}

int
hashtab_get_index(unsigned *idx, struct hashtab *st, void *key, int *install)
{
	int rc;
	unsigned i, pos;
	struct hashent *elem;
  
	if (!st->tab) {
		if (install) {
			rc = hashtab_rehash(st);
			if (rc)
				return rc;
		} else
			return ENOENT;
	}

	pos = st->hash_fun(key, hash_size[st->hash_num]);

	for (i = pos; elem = st->tab[i];) {
		if (st->cmp_fun(elem, key) == 0) {
			if (install)
				*install = 0;
			*idx = i; 
			return 0;
		}
      
		if (++i >= hash_size[st->hash_num])
			i = 0;
		if (i == pos)
			break;
	}

	if (!install)
		return ENOENT;
  
	if (!elem) {
		*install = 1;
		*idx = i;
		return 0;
	}

	if ((rc = hashtab_rehash(st)) != 0)
		return rc;

	return hashtab_get_index(idx, st, key, install);
}

void *
hashtab_lookup_or_install(struct hashtab *st, void *key, int *install)
{
	unsigned i;
	int rc = hashtab_get_index(&i, st, key, install);
	if (rc == 0) {
		if (install && *install == 1) {
			struct hashent *ent = hashent_alloc(st, key);
			if (!ent) {
				errno = ENOMEM;
				return NULL;
			}
			st->tab[i] = ent;
			return ent;
		} else
			return st->tab[i];
	}
	errno = rc;
	return NULL;
}

void
hashtab_clear(struct hashtab *st)
{
	unsigned i, hs;
  
	if (!st || !st->tab)
		return;

	hs = hash_size[st->hash_num];
	for (i = 0; i < hs; i++) {
		struct hashent *elem = st->tab[i];
		if (elem) {
			hashent_free(st, elem);
			st->tab[i] = NULL;
		}
	}
}

struct hashtab *
hashtab_create(size_t elsize, 
	       unsigned (*hash_fun)(void *, unsigned long),
	       int (*cmp_fun)(const void *, const void *),
	       int (*copy_fun)(void *, void *),
	       void *(*alloc_fun)(size_t), void (*free_fun)(void *))
{
	struct hashtab *st = malloc(sizeof(*st));
	if (st) {
		memset(st, 0, sizeof(*st));
		st->elsize = elsize;
		st->hash_fun = hash_fun;
		st->cmp_fun = cmp_fun;
		st->copy_fun = copy_fun;
		st->hashent_alloc_fun = alloc_fun;
		st->hashent_free_fun = free_fun;
		st->tab = calloc(hash_size[st->hash_num], sizeof(*st->tab));
		if (!st->tab) {
			free(st);
			st = NULL;
		}
	}
	return st;
}

void
hashtab_free(struct hashtab *st)
{
	if (st) {
		hashtab_clear(st);
		free(st->tab);
		free(st);
	}
}

size_t
hashtab_count_entries(struct hashtab *st)
{
	unsigned i;
	size_t count = 0;
	
	for (i = 0; i < hash_size[st->hash_num]; i++)
		if (st->tab[i])
			count++;
	return count;
}

int
hashtab_foreach(struct hashtab *st, hashtab_enumerator_t fun, void *data)
{
	unsigned i;

	if (!st)
		return 0;
	for (i = 0; i < hash_size[st->hash_num]; i++) {
		struct hashent *ep = st->tab[i];
		if (ep) {
			int rc = fun(ep, data);
			if (rc)
				return rc;
		}
	}
	return 0;
}

size_t
hashtab_count(struct hashtab *st)
{
	unsigned i;
	size_t count = 0;
	
	if (!st)
		return 0;
	for (i = 0; i < hash_size[st->hash_num]; i++) {
		if (st->tab[i])
			++count;
	}
	return count;
}







   
