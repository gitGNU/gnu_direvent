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
#include <dirent.h>
#include <sys/stat.h>

void
dirwatcher_ref(struct dirwatcher *dw)
{
	++dw->refcnt;
}

void
dirwatcher_unref(struct dirwatcher *dw)
{
	if (--dw->refcnt)
		return;
	free(dw->dirname);
	direvent_handler_list_unref(dw->handler_list);
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

struct hashtab *nametab;

struct dirwatcher *
dirwatcher_install(const char *path, int *pnew)
{
	struct dirwatcher *dw, dwkey;
	struct dwref key;
	struct dwref *ent;
	int install = 1;

	if (!nametab) {
		nametab = hashtab_create(sizeof(struct dwref),
					 dwname_hash, dwname_cmp, dwname_copy,
					 NULL, dwref_free);
		if (!nametab) {
			diag(LOG_CRIT, N_("not enough memory"));
			exit(1);
		}
	}

	dwkey.dirname = (char*) path;
	key.dw = &dwkey;
	ent = hashtab_lookup_or_install(nametab, &key, &install);
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

struct dirwatcher *
dirwatcher_lookup(const char *dirname)
{
	struct dirwatcher dwkey;
	struct dwref key;
	struct dwref *ent;

	if (!nametab)
		return NULL;
	
	dwkey.dirname = (char*) dirname;
	key.dw = &dwkey;
	ent = hashtab_lookup_or_install(nametab, &key, NULL);
	return ent ? ent->dw : NULL;
}

static void
dirwatcher_remove(const char *dirname)
{
	struct dirwatcher dwkey;
	struct dwref key;

	if (!nametab)
		return;
	
	dwkey.dirname = (char*) dirname;
	key.dw = &dwkey;
	hashtab_remove(nametab, &key);
}

void
dirwatcher_destroy(struct dirwatcher *dwp)
{
	debug(1, (_("removing watcher %s"), dwp->dirname));
	sysev_rm_watch(dwp);
	dirwatcher_remove(dwp->dirname);
	if (hashtab_count(nametab) == 0) {
		diag(LOG_CRIT, _("no watchers left; exiting now"));
		stop = 1;
	}
}

int 
dirwatcher_init(struct dirwatcher *dwp)
{
	event_mask mask = { 0, 0 };
	struct handler *hp;
	direvent_handler_iterator_t itr;
	
	int wd;

	debug(1, (_("creating watcher %s"), dwp->dirname));

	for_each_handler(dwp, itr, hp) {
		mask.sys_mask |= hp->ev_mask.sys_mask;
		mask.gen_mask |= hp->ev_mask.gen_mask;
	}
	
	wd = sysev_add_watch(dwp, mask);
	if (wd == -1) {
		diag(LOG_ERR, _("cannot set watcher on %s: %s"),
		     dwp->dirname, strerror(errno));
		return 1;
	}

	dwp->wd = wd;

	return 0;
}

static int watch_subdirs(struct dirwatcher *parent, int notify);

int
subwatcher_create(struct dirwatcher *parent, const char *dirname,
		  int isdir, int notify)
{
	struct dirwatcher *dwp;
	int inst;
	
	dwp = dirwatcher_install(dirname, &inst);
	if (!inst)
		return -1;

	dwp->handler_list = direvent_handler_list_copy(parent->handler_list);
	dwp->parent = parent;
	
	if (parent->depth == -1)
		dwp->depth = parent->depth;
	else if (parent->depth)
		dwp->depth = parent->depth - 1;
	else
		dwp->depth = 0;
	
	if (dirwatcher_init(dwp)) {
		//FIXME dirwatcher_free(dwp);
		return -1;
	}

	return 1 + (isdir ? watch_subdirs(dwp, notify) : 0);
}

/* Deliver GENEV_CREATE event */
void
deliver_ev_create(struct dirwatcher *dp, const char *name)
{
	event_mask m = { GENEV_CREATE, 0 };
	struct handler *h;
	direvent_handler_iterator_t itr;
	
	for_each_handler(dp, itr, h) {
		if (handler_matches_event(h, gen, GENEV_CREATE, name))
			run_handler(h, &m, dp->dirname, name);
	}
}

/* Check if a new watcher must be created and create it if so.

   A watcher must be created if its parent's recursion depth has a non-null
   value.  If it has a negative value, which means "recursively watch new
   subdirectories without limit on their nesting level", it will be inherited
   by the new watcher.  Otherwise, the new watcher will inherit the parent's
   depth decreased by one, thus eventually cutting off creation of new
   watchers.

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
		diag(LOG_ERR,
		     _("cannot create watcher %s/%s: not enough memory"),
		     dir, name);
		return -1;
	}

	if (stat(fname, &st)) {
		diag(LOG_ERR,
		     _("cannot create watcher %s/%s, stat failed: %s"),
		     dir, name, strerror(errno));
		rc = -1;
	} else if (S_ISDIR(st.st_mode)) {
		deliver_ev_create(parent, name);
		rc = subwatcher_create(parent, fname, 1, 1);
	} else
		rc = 0;
	free(fname);
	return rc;
}

int
dirwatcher_pattern_match(struct dirwatcher *dwp, const char *file_name)
{
	struct handler *hp;
	direvent_handler_iterator_t itr;

	for_each_handler(dwp, itr, hp) {
		if (filename_pattern_match(hp->fnames, file_name) == 0)
			return 0;
	}
	return 1;
}

/* Recursively scan subdirectories of parent and add them to the
   watcher list, as requested by the parent's recursion depth value. */
static int
watch_subdirs(struct dirwatcher *parent, int notify)
{
	DIR *dir;
	struct dirent *ent;
	int filemask = sysev_filemask(parent);
	int total = 0;

	if (parent->depth)
		filemask |= S_IFDIR;
	if (!filemask)
		return 0;
	
	dir = opendir(parent->dirname);
	if (!dir) {
		diag(LOG_ERR, _("cannot open directory %s: %s"),
		     parent->dirname, strerror(errno));
		return 0;
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
			diag(LOG_ERR,
			     _("cannot stat %s/%s: not enough memory"),
			     parent->dirname, ent->d_name);
			continue;
		}
		if (stat(dirname, &st)) {
			diag(LOG_ERR, _("cannot stat %s: %s"),
			     dirname, strerror(errno));
		} else if (dirwatcher_pattern_match(parent, ent->d_name)
			   == 0) {
			if (notify)
				deliver_ev_create(parent, ent->d_name);
			if (st.st_mode & filemask) {
				int rc = subwatcher_create(parent, dirname,
							   S_ISDIR(st.st_mode),
							   notify);
				if (rc > 0)
					total += rc;
			}
		}
		free(dirname);
	}
	closedir(dir);
	return total;
}


static int
setwatcher(struct hashent *ent, void *data)
{
	struct dwref *dwref = (struct dwref *) ent;
	struct dirwatcher *dwp = dwref->dw;
	int *success = data;
	
	if (dwp->wd == -1 && dirwatcher_init(dwp) == 0)
		watch_subdirs(dwp, 0);
	if (dwp->wd >= 0)
		*success = 1;
	return 0;
}

void
setup_watchers(void)
{
	int success = 0;
	
	sysev_init();
	if (hashtab_count(nametab) == 0) {
		diag(LOG_CRIT, _("no event handlers configured"));
		exit(1);
	}
	hashtab_foreach(nametab, setwatcher, &success);
	if (!success) {
		diag(LOG_CRIT, _("no event handlers installed"));
		exit(2);
	}
}

static int
stopwatcher(struct hashent *ent, void *data)
{
	struct dwref *dwref = (struct dwref *) ent;
	struct dirwatcher *dwp = dwref->dw;
	debug(1, (_("removing watcher %s"), dwp->dirname));
	sysev_rm_watch(dwp);
	return 0;
}

void
shutdown_watchers(void)
{
	hashtab_foreach(nametab, stopwatcher, NULL);
	hashtab_clear(nametab);
}


char *
split_pathname(struct dirwatcher *dp, char **dirname)
{
	char *p = strrchr(dp->dirname, '/');
	if (p) {
		dp->split_p = p;
		*p++ = 0;
		*dirname = dp->dirname;
	} else {
		p = dp->dirname;
		*dirname = ".";
	}
	return p;
}

void
unsplit_pathname(struct dirwatcher *dp)
{
	if (dp->split_p) {
		*dp->split_p = '/';
		dp->split_p = NULL;
	}
}
