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
#include <sys/event.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>

struct event events[] = {
	{ NOTE_DELETE, "delete" },
	{ NOTE_WRITE,  "write" },
	{ NOTE_EXTEND, "extend" },
	{ NOTE_ATTRIB, "attrib" },
	{ NOTE_LINK,   "link" },
	{ NOTE_RENAME, "rename" },
	{ NOTE_REVOKE, "revoke" },
	{ 0, NULL }
};

int
evsys_name_to_code(const char *name)
{
	int i;

	for (i = 0; events[i].evname; i++) {
		if (strcmp(events[i].evname, name) == 0)
			return events[i].evcode;
	}
	return 0;
}

const char *
evsys_code_to_name(int code)
{
	int i;

	for (i = 0; events[i].evname; i++) {
		if (events[i].evcode & code)
			return events[i].evname;
	}
	return NULL;
}

static void
ev_log(struct kevent *ep, struct dirwatcher *dp)
{
	int i;

	if (debug_level > 0) {
		for (i = 0; events[i].evname; i++) {
			if (events[i].evcode & ep->fflags)
				debug(1, ("%s: %s", dp->dirname,
					  events[i].evname));
		}
	}
}
		

static int kq;
static struct kevent *evtab;
static struct kevent *chtab;
static int chcnt;
static int chclosed = -1;

int evsys_filemask = S_IFMT;

void
evsys_init()
{
	kq = kqueue();
	if (kq == -1) {
		diag(LOG_CRIT, "kqueue: %s", strerror(errno));
		exit(1);
	}
	evtab = calloc(sysconf(_SC_OPEN_MAX), sizeof(evtab[0]));
	chtab = calloc(sysconf(_SC_OPEN_MAX), sizeof(chtab[0]));
}

int
evsys_add_watch(struct dirwatcher *dwp, int mask)
{
	int wd = open(dwp->dirname, O_RDONLY);
	if (wd >= 0) {
		struct stat st;
		if (fstat(wd, &st)) {
			close(wd);
			return -1;
		}
		dwp->file_mode = st.st_mode;
		dwp->file_ctime = st.st_ctime;
		EV_SET(chtab + chcnt, wd, EVFILT_VNODE,
		       EV_ADD | EV_ENABLE | EV_CLEAR, mask,
		       0, dwp);
		wd = chcnt++;
	}
	return wd;
}

void
evsys_rm_watch(struct dirwatcher *dwp)
{
	close(chtab[dwp->wd].ident);
	chtab[dwp->wd].ident = -1;
	if (chclosed == -1 || chclosed > dwp->wd)
		chclosed = dwp->wd;
}

static void
chclosed_elim()
{
	int i, j;
	
	if (chclosed == -1)
		return;

	for (i = chclosed, j = chclosed + 1; j < chcnt; j++)
		if (chtab[j].ident != -1) {
			struct dirwatcher *dwp;
			
			chtab[i] = chtab[j];
			dwp = chtab[i].udata;
			dwp->wd = i;
			i++;
		}
	chcnt = i;
	chclosed = -1;
}

static char const *
filename(struct dirwatcher *dp)
{
	if (!dp->parent)
		return dp->dirname;
	return dp->dirname + strlen(dp->parent->dirname) + 1;
}

static void
check_created(struct dirwatcher *dp)
{
	DIR *dir;
	struct dirent *ent;

	dir = opendir(dp->dirname);
	if (!dir) {
		diag(LOG_ERR, "cannot open directory %d: %s",
		     dp->dirname, strerror(errno));
		return;
	}

	while (ent = readdir(dir)) {
		struct stat st;
		char *pathname;
		
		if (ent->d_name[0] == '.' &&
		    (ent->d_name[1] == 0 ||
		     (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
			continue;
		
		pathname = mkfilename(dp->dirname, ent->d_name);
		if (!pathname) {
			diag(LOG_ERR, "cannot stat %s/%s: not enough memory",
			     dp->dirname, ent->d_name);
			continue;
		}

		if (stat(pathname, &st)) {
			diag(LOG_ERR, "cannot stat %s: %s",
			     pathname, strerror(errno));
		} else if (st.st_ctime > dp->file_ctime) {
			watch_pathname(dp, pathname, S_ISDIR(st.st_mode));
			dp->file_ctime = st.st_ctime;
		}
		free(pathname);
	}
	closedir(dir);
}

static void
process_event(struct kevent *ep)
{
	struct dirwatcher *dp = ep->udata;
	struct handler *h;

	if (!dp) {
		diag(LOG_NOTICE, "unrecognized event %x", ep->fflags);
		return;
	}

	ev_log(ep, dp);

	if (S_ISDIR(dp->file_mode)) {
		/* Check if new files have appeared. */
		if (ep->fflags & NOTE_WRITE)
			check_created(dp);
		return;
	}

	for (h = dp->handler_list; h; h = h->next) {
		if (h->ev_mask & ep->fflags)
			run_handler(dp->parent, h, ep->fflags, filename(dp));
	}

	if (ep->fflags & NOTE_DELETE) {
		debug(1, ("%s deleted", dp->dirname));
		dirwatcher_destroy(dp);
		return;
	}
}	


int
evsys_select()
{
	int i, n;
	
	chclosed_elim();
	n = kevent(kq, chtab, chcnt, evtab, chcnt, NULL);
	if (n == -1) {
		if (signo == SIGCHLD || signo == SIGALRM)
			return 0;
		diag(LOG_NOTICE, "got signal %d", signo);
		return 1;
	} 

	for (i = 0; i < n; i++) 
		process_event(&evtab[i]);

	return 0;
}
		
