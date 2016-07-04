/* direvent - directory content watcher daemon
   Copyright (C) 2012-2016 Sergey Poznyakoff

   Direvent is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   Direvent is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with direvent. If not, see <http://www.gnu.org/licenses/>. */

#include "direvent.h"


struct symevt {
	int used;
	char *name;
	event_mask mask;
	int line;
};

struct hashtab *evtab;

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
defevt(const char *name, event_mask *mask, int line)
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
	evp->mask = *mask;
	evp->line = line;
	return 0;
}

int
getevt(const char *name, event_mask *mask)
{
	if (evtab) {
		struct symevt key, *evp;
		key.name = (char *) name;
		evp = hashtab_lookup_or_install(evtab, &key, NULL);
		if (evp) {
			*mask = evp->mask;
			return 0;
		}
	}
	if (trans_strtotok(sysev_transtab, name, &mask->sys_mask))
		return -1;
	mask->gen_mask = 0;
	return 0;
}

int
evtnullp(event_mask *mask)
{
	return mask->gen_mask == 0 && mask->sys_mask == 0;
}

struct transtab genev_transtab[] = {
	{ "create", GENEV_CREATE },
	{ "write",  GENEV_WRITE  },
	{ "attrib", GENEV_ATTRIB },
	{ "delete", GENEV_DELETE },
	{ NULL }
};

event_mask *
event_mask_init(event_mask *m, int fflags, event_mask const *req)
{
	int i;

	m->sys_mask = fflags & req->sys_mask;
	m->gen_mask = 0;
	for (i = 0; i < genev_xlat[i].gen_mask; i++)
		if (genev_xlat[i].sys_mask & m->sys_mask)
			m->gen_mask |= genev_xlat[i].gen_mask;
	if (req->gen_mask)
		m->gen_mask &= req->gen_mask;
	return m;
}

void
evtsetall(event_mask *m)
{
	int i;
	
	m->sys_mask = 0;
	m->gen_mask = 0;
	for (i = 0; i < genev_xlat[i].gen_mask; i++) {
		m->gen_mask |= genev_xlat[i].gen_mask;
		m->sys_mask |= genev_xlat[i].sys_mask;
	}
}
