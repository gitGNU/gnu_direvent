/* dircond - directory content watcher daemon
   Copyright (C) 2012, 2013 Sergey Poznyakoff

   Dircond is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   Dircond is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with dircond. If not, see <http://www.gnu.org/licenses/>. */

#include "dircond.h"


struct symevt {
	int used;
	char *name;
	int mask;
	int line;
};

struct hashtab *evtab;

static unsigned
symevt_hash(void *data, unsigned long hashsize)
{
	struct symevt *sym = data;
	return hash_string(sym->name, hashsize);
}

static int
symevt_cmp(const void *a, const void *b)
{
	struct symevt const *syma = a;
	struct symevt const *symb = b;

	return strcmp(syma->name, symb->name);
}

static int
symevt_copy(void *a, void *b)
{
	struct symevt *syma = a;
	struct symevt *symb = b;

	syma->used = 1;
	syma->name = estrdup(symb->name);
	return 0;
}

static void
symevt_free(void *p)
{
	struct symevt *sym = p;
	free(sym->name);
	free(sym);
}


int
defevt(const char *name, int mask, int line)
{
	struct symevt key, *evp;
	int install = 1;
	
	if (!evtab) {
		evtab = hashtab_create(sizeof(struct symevt),
				       symevt_hash, symevt_cmp,
				       symevt_copy,
				       NULL, symevt_free);
		if (!evtab) {
			diag(LOG_CRIT, "not enough memory");
			exit(1);
		}
	}

	key.name = (char *) name;
	evp = hashtab_lookup_or_install(evtab, &key, &install);
	if (!install)
		return evp->line;
	evp->mask = mask;
	evp->line = line;
	return 0;
}

int
getevt(const char *name)
{
	if (evtab) {
		struct symevt key, *evp;
		key.name = (char *) name;
		evp = hashtab_lookup_or_install(evtab, &key, NULL);
		if (evp)
			return evp->mask;
	}
	return evsys_name_to_code(name);
}
