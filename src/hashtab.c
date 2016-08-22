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

struct hashent_list_entry {
	struct hashent_list_entry *prev, *next;
	struct hashent *ent;
};

struct hashent_list {
	struct hashent_list_entry *head, *tail;
};

struct hashtab {
	unsigned int hash_num;  /* Index to hash_size table */
	size_t elsize;          /* Size of an element */
	size_t elcount;         /* Number of elements in use */
	struct hashent **tab;
	unsigned (*hash_fun)(void *, unsigned long hash_num);
	int (*cmp_fun)(const void *, const void *);
	int (*copy_fun)(void *, void *);
	void *(*hashent_alloc_fun)(size_t size);
	void (*hashent_free_fun) (void *);
	
	unsigned int itr_level;
	struct hashent_list list_new, list_del;
};

static void
hashent_list_init(struct hashent_list *list)
{
	list->head = NULL;
	list->tail = NULL;
}

static int
hashent_list_append(struct hashent_list *list, struct hashent *ent)
{
	struct hashent_list_entry *hent = malloc(sizeof(*hent));
	if (!hent)
		return -1;
	hent->ent = ent;
	hent->next = NULL;
	hent->prev = list->tail;
	if (list->tail)
		list->tail->next = hent;
	else
		list->head = hent;
	list->tail = hent;
	return 0;
}

static void
hashent_list_remove(struct hashent_list *list, struct hashent_list_entry *hent)
{
	struct hashent_list_entry *p;
	if ((p = hent->prev))
		p->next = hent->next;
	else
		list->head = hent->next;
	if ((p = hent->next))
		p->prev = hent->prev;
	else
		list->tail = hent->prev;
	free(hent);
}

static struct hashent_list_entry *
hashent_list_lookup(struct hashtab *st, struct hashent_list *list,
		    struct hashent *ent)
{
	struct hashent_list_entry *p;
	for (p = list->head; p; p = p->next) {
		if (st->cmp_fun(p->ent, ent) == 0)
			return p;
	}
	return NULL;
}

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

	if (st->itr_level) {
		struct hashent_list_entry *hent;
		hent = hashent_list_lookup(st, &st->list_new, elt);
		if (hent) {
			entry = hent->ent;
			hashent_list_remove(&st->list_new, hent);
			hashent_free(st, entry);
			return 0;
		}			
	}
	
	pos = st->hash_fun(elt, hash_size[st->hash_num]);
	for (i = pos; entry = st->tab[i];) {
		if (st->cmp_fun(entry, elt) == 0)
			break;
		if (++i >= hash_size[st->hash_num])
			i = 0;
		if (i == pos)
			return ENOENT;
	}

	if (!entry)
#if 0
		return ENOENT;
#else
	        abort();
#endif

	if (st->itr_level) {
		if (hashent_list_append(&st->list_del, entry))
			return ENOMEM;
		entry->used = 0;
	}
		
	hashent_free(st, entry);
	st->elcount--;
	
	for (;;) {
		st->tab[i] = NULL;
		j = i;

		do {
			if (++i >= hash_size[st->hash_num])
				i = 0;
			if (!st->tab[i])
				return 0;
			r = st->hash_fun(st->tab[i], hash_size[st->hash_num]);
		} while ((j < r && r <= i)
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
			if (st->itr_level) {
				if (hashent_list_append(&st->list_new, ent)) {
					int ec = errno;
					hashent_free(st, ent);
					errno = ec;
					return NULL;
				}
				return ent;
			}
			st->tab[i] = ent;
			st->elcount++;
			return ent;
		} else
			return st->tab[i];
	} else if (rc == ENOENT && st->itr_level) {
		struct hashent_list_entry *hent;
		hent = hashent_list_lookup(st, &st->list_new, key);
		if (hent)
			return hent->ent;
		rc = ENOENT;
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
	st->elcount = 0;
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
		st->elcount = 0;
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

int
hashtab_foreach(struct hashtab *st, hashtab_enumerator_t fun, void *data)
{
	unsigned i;

	if (!st)
		return 0;

	if (st->itr_level++ == 0) {
		hashent_list_init(&st->list_new);
		hashent_list_init(&st->list_del);
	}
	
	for (i = 0; i < hash_size[st->hash_num]; i++) {
		struct hashent *ep = st->tab[i];
		if (ep) {
			int rc = fun(ep, data);
			if (rc)
				return rc;
		}
	}

	if (--st->itr_level == 0) {
		while (st->list_del.head) {
			struct hashent *ent = st->list_del.head->ent;
			hashent_list_remove(&st->list_del, st->list_del.head);
			hashtab_remove(st, ent);
		}

		while (st->list_new.head) {
			struct hashent *ent = st->list_new.head->ent;
			unsigned i;
			int install = 1;
			if (hashtab_get_index(&i, st, ent, &install) == 0) {
				st->tab[i] = ent;
				st->elcount++;
			}
			hashent_list_remove(&st->list_new, st->list_new.head);
		}
	}
	
	return 0;
}

size_t
hashtab_count(struct hashtab *st)
{
	return st ? st->elcount : 0;
}







   
