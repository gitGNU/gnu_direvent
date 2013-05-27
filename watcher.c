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
#include <dirent.h>
#include <sys/stat.h>

void
dirwatcher_unref(struct dirwatcher *dw)
{
	if (--dw->refcnt)
		return;
	free(dw->dirname);
	free(dw);
}


struct dwref {
	int used;
	struct dirwatcher *dw;
};

static unsigned
dwname_hash(void *data, unsigned long hashsize)
{
	struct dwref *sym = data;
	return hash_string(sym->dw->dirname, hashsize);
}

static int
dwname_cmp(const void *a, const void *b)
{
	struct dwref const *syma = a;
	struct dwref const *symb = b;

	return strcmp(syma->dw->dirname, symb->dw->dirname);
}

static int
dwname_copy(void *a, void *b)
{
	struct dwref *syma = a;
	struct dwref *symb = b;

	syma->used = 1;
	syma->dw = symb->dw;
	return 0;
}

static void
dwref_free(void *p)
{
	struct dwref *dwref = p;
	dirwatcher_unref(dwref->dw);
	free(dwref);
}

struct hashtab *texttab;

struct dirwatcher *
dirwatcher_install(const char *path, int *pnew)
{
	struct dirwatcher *dw, dwkey;
	struct dwref key;
	struct dwref *ent;
	int install = 1;

	if (!texttab) {
		texttab = hashtab_create(sizeof(struct dwref),
					 dwname_hash, dwname_cmp, dwname_copy,
					 NULL, dwref_free);
		if (!texttab) {
			diag(LOG_CRIT, "not enough memory");
			exit(1);
		}
	}

	dwkey.dirname = (char*) path;
	key.dw = &dwkey;
	ent = hashtab_lookup_or_install(texttab, &key, &install);
	if (install) {
		dw = ecalloc(1, sizeof(*dw));
		dw->dirname = estrdup(path);
		dw->wd = -1;
		dw->refcnt++;
		ent->dw = dw;
	}
	if (!ent)
		abort(); /* FIXME */
	if (pnew)
		*pnew = install;
	return ent->dw;
}

static struct dirwatcher *
dirwatcher_lookup(const char *dirname)
{
	struct dirwatcher dwkey;
	struct dwref key;
	struct dwref *ent;

	if (!texttab)
		return NULL;
	
	dwkey.dirname = (char*) dirname;
	key.dw = &dwkey;
	ent = hashtab_lookup_or_install(texttab, &key, NULL);
	return ent ? ent->dw : NULL;
}

static void
dirwatcher_remove(const char *dirname)
{
	struct dirwatcher dwkey;
	struct dwref key;

	if (!texttab)
		return;
	
	dwkey.dirname = (char*) dirname;
	key.dw = &dwkey;
	hashtab_remove(texttab, &key);
}


struct hashtab *watchtab;

static unsigned
dw_hash(void *data, unsigned long hashsize)
{
	struct dwref *ent = data;
	return ent->dw->wd % hashsize;
}

static int
dw_cmp(const void *a, const void *b)
{
	struct dwref const *ha = a;
	struct dwref const *hb = b;
	return ha->dw->wd != hb->dw->wd;
}

static int
dw_copy(void *a, void *b)
{
	struct dwref *ha = a;
	struct dwref *hb = b;

	ha->used = 1;
	ha->dw = hb->dw;
	ha->dw->refcnt++;
	return 0;
}

struct hashtab *dwtab;

void
dirwatcher_register(struct dirwatcher *dw)
{
	struct dwref key;
	struct dwref *ent;
	int install = 1;

	if (!dwtab) {
		dwtab = hashtab_create(sizeof(struct dwref),
				       dw_hash, dw_cmp, dw_copy,
				       NULL, dwref_free);
		if (!dwtab) {
			diag(LOG_ERR, "not enough memory");
			exit(1);
		}
	}

	memset(&key, 0, sizeof(key));
	key.dw = dw;
	ent = hashtab_lookup_or_install(dwtab, &key, &install);
	if (!ent) {
		diag(LOG_ERR, "not enough memory");
		exit(1);
	}
}

struct dirwatcher *
dirwatcher_lookup_wd(int wd)
{
	struct dirwatcher dwkey;
	struct dwref dwref, *ent;

	if (!dwtab) 
		return NULL;
	dwkey.wd = wd;
	dwref.dw = &dwkey;
	ent = hashtab_lookup_or_install(dwtab, &dwref, NULL);
	return ent ? ent->dw : NULL;
}

void
dirwatcher_remove_wd(int wd)
{
	struct dirwatcher dwkey;
	struct dwref dwref;

	if (!dwtab) 
		return;
	dwkey.wd = wd;
	dwref.dw = &dwkey;
	hashtab_remove(dwtab, &dwref);
}


int 
dirwatcher_init(struct dirwatcher *dwp)
{
	int mask = 0;
	struct handler *hp;
	int wd;

	debug(1, ("creating watcher %s", dwp->dirname));

	for (hp = dwp->handler_list; hp; hp = hp->next)
		mask |= hp->ev_mask;
	
	wd = evsys_add_watch(dwp, mask);
	if (wd == -1) {
		diag(LOG_ERR, "cannot set watch on %s: %s",
		     dwp->dirname, strerror(errno));
		return 1;
	}

	dwp->wd = wd;
	dirwatcher_register(dwp);

	return 0;
}

static struct dirwatcher *
subwatcher_create(struct dirwatcher *parent, const char *dirname)
{
	struct dirwatcher *dwp;
	int inst;
	
	dwp = dirwatcher_install(dirname, &inst);
	if (!inst)
		return 0;

	dwp->handler_list = parent->handler_list;
	dwp->parent = parent;
	
	if (parent->depth == -1)
		dwp->depth = parent->depth;
	else if (parent->depth)
		dwp->depth = parent->depth - 1;
	else
		dwp->depth = 0;
	
	if (dirwatcher_init(dwp)) {
		//FIXME dirwatcher_free(dwp);
		return NULL;
	}
	return dwp;
}

/* Check if a new watcher must be created and create it if so.

   A watcher must be created if its parent's autowatch has a non-null
   value.  If it has a negative value, it will be inherited by the new
   watcher.  Otherwise, the new watcher will inherit the parent's autowatch
   decreased by one.

   Return 0 on success, -1 on error.
*/
int
check_new_watcher(const char *dir, const char *name)
{
	int rc;
	char *fname;
	struct stat st;
	struct dirwatcher *parent;

	parent = dirwatcher_lookup(dir);
	if (!parent || !parent->depth)
		return 0;
	
	fname = mkfilename(dir, name);
	if (!fname) {
		diag(LOG_ERR, "cannot create watcher %s/%s: not enough memory",
		     dir, name);
		return -1;
	}

	if (stat(fname, &st)) {
		diag(LOG_ERR, "cannot create watcher %s/%s, stat failed: %s",
		     dir, name, strerror(errno));
		rc = -1;
	} else if (S_ISDIR(st.st_mode))
		rc = subwatcher_create(parent, fname) ? 0 : -1;
	else
		rc = 0;
	free(fname);
	return rc;
}

/* Recursively scan subdirectories of parent and add them to the
   watcher list, as requested by the parent's autowatch value. */
static void
watch_subdirs(struct dirwatcher *parent)
{
	DIR *dir;
	struct dirent *ent;
	int filemask = evsys_filemask;
	
	if (parent->depth)
		evsys_filemask |= S_IFDIR;
	if (!evsys_filemask)
		return;
	
	dir = opendir(parent->dirname);
	if (!dir) {
		diag(LOG_ERR, "cannot open directory %s: %s",
		     parent->dirname, strerror(errno));
		return;
	}

	while (ent = readdir(dir)) {
		struct stat st;
		char *dirname;
		
		if (ent->d_name[0] == '.' &&
		    (ent->d_name[1] == 0 ||
		     (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
			continue;
		
		dirname = mkfilename(parent->dirname, ent->d_name);
		if (!dirname) {
			diag(LOG_ERR, "cannot stat %s/%s: not enough memory",
			     parent->dirname, ent->d_name);
			continue;
		}
		if (stat(dirname, &st)) {
			diag(LOG_ERR, "cannot stat %s: %s",
			     dirname, strerror(errno));
		} else if (st.st_mode & filemask) {
			struct dirwatcher *dwp =
				subwatcher_create(parent, dirname);
			if (dwp && S_ISDIR(st.st_mode))
				watch_subdirs(dwp);
		}
		free(dirname);
	}
	closedir(dir);
}


int
setwatcher(struct hashent *ent, void *null)
{
	struct dwref *dwref = (struct dwref *) ent;
	struct dirwatcher *dwp = dwref->dw;
	
	if (dwp->wd == -1 && dirwatcher_init(dwp) == 0)
		watch_subdirs(dwp);
	return 0;
}

void
setup_watchers()
{
	if (hashtab_count(texttab) == 0) {
		diag(LOG_CRIT, "no event handlers configured");
		exit(1);
	}
	hashtab_foreach(texttab, setwatcher, NULL);
	if (hashtab_count(dwtab) == 0) {
		diag(LOG_CRIT, "no event handlers installed");
		exit(2);
	}
}

void
dirwatcher_destroy(struct dirwatcher *dwp)
{
	debug(1, ("removing watcher %s", dwp->dirname));
	evsys_rm_watch(dwp);

	dirwatcher_remove_wd(dwp->wd);
	dirwatcher_remove(dwp->dirname);
}

/* Remove a watcher identified by its directory and file name */
void
remove_watcher(const char *dir, const char *name)
{
	struct dirwatcher *dwp;
	char *fullname = mkfilename(dir, name);
	if (!fullname) {
		diag(LOG_EMERG, "not enough memory: "
		     "cannot look up a watcher to delete");
		return;
	}
	dwp = dirwatcher_lookup(fullname);
	free(fullname);
	if (dwp)
		dirwatcher_destroy(dwp);
}
