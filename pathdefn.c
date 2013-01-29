/* This file is part of Dircond.
   Copyright (C) 2012, 2013 Sergey Poznyakoff.
 
   Dircond is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.
 
   Dircond is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with Dircond.  If not, see <http://www.gnu.org/licenses/>. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "dircond.h"

unsigned
hash_string(const char *name, unsigned long hashsize)
{
	unsigned i;
	
	for (i = 0; *name; name++) {
		i <<= 1;
		i ^= *(unsigned char*) name;
	}
	return i % hashsize;
}		

static unsigned
pathdefn_hash(void *data, unsigned long hashsize)
{
	struct pathdefn *sym = data;
	return hash_string(sym->name, hashsize);
}

static int
pathdefn_cmp(const void *a, const void *b)
{
	struct pathdefn const *syma = a;
	struct pathdefn const *symb = b;

	return strcmp(syma->name, symb->name);
}

static int
pathdefn_copy(void *a, void *b)
{
	struct pathdefn *syma = a;
	struct pathdefn *symb = b;

	syma->used = 1;
	syma->name = strdup(symb->name);
	return syma->name == NULL;
}

static void
pathdefn_free(void *p)
{
	free(p);
}

static struct hashtab *pathtab;

/* FIXME: Should exit gracefully on out of memory errors */
int
pathdefn_add(const char *name, const char *dir, long depth)
{
	struct pathdefn key;
	struct pathdefn *defn;
	struct pathent *ent, *p, *prev;
	int install = 1;
	size_t len;
	
	len = strlen(dir);
	while (len > 0 && dir[len-1] == '/')
		--len;

	if (len == 0)
		return 0;
		
	if (!pathtab) {
		pathtab = hashtab_create(sizeof(struct pathdefn),
					 pathdefn_hash, pathdefn_cmp,
					 pathdefn_copy,
					 NULL, pathdefn_free);
		if (!pathtab) {
			diag(LOG_CRIT, "not enough memory");
			exit(1);
		}
	}

	memset(&key, 0, sizeof(key));
	key.name = (char*) name;
	defn = hashtab_lookup_or_install(pathtab, &key, &install);
	if (!defn) {
		diag(LOG_CRIT, "not enough memory");
		exit(1);
	}

	prev = NULL;
	for (p = defn->pathlist; p; prev = p, p = p->next) {
		if (p->len == len && strncmp(p->path, dir, len) == 0)
			return 0;
	}

	ent = emalloc(sizeof(*ent) + len);
	strcpy(ent->path, dir);
	ent->len = len;
	ent->depth = depth;
	if (prev)
		prev->next = ent;
	else
		defn->pathlist = ent;
	
	return 0;
}

struct pathent *
pathdefn_get(const char *name)
{
	struct pathdefn key;
	struct pathdefn *defn;

	if (!pathtab)
		return NULL;
	memset(&key, 0, sizeof(key));
	key.name = (char *) name;
	defn = hashtab_lookup_or_install(pathtab, &key, NULL);
	if (!defn) {
		diag(LOG_CRIT, "not enough memory");
		exit(1);
	}
	return defn ? defn->pathlist : NULL;
}
