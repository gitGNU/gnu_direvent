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
#include <signal.h>
#include <sys/inotify.h>


/* Event codes */
struct transtab sysev_transtab[] = {
	{ "ACCESS",        IN_ACCESS         },
	{ "ATTRIB",        IN_ATTRIB         },       
	{ "CLOSE_WRITE",   IN_CLOSE_WRITE    },  
	{ "CLOSE_NOWRITE", IN_CLOSE_NOWRITE  },
	{ "CREATE",        IN_CREATE         },       
	{ "DELETE",        IN_DELETE         },      
	{ "MODIFY",        IN_MODIFY         },
	{ "MOVED_FROM",    IN_MOVED_FROM     },    
	{ "MOVED_TO",      IN_MOVED_TO       },      
	{ "OPEN",          IN_OPEN           },
	{ 0 }
};

event_mask genev_xlat[] = {
	{ GENEV_CREATE, IN_CREATE|IN_MOVED_TO },
	{ GENEV_WRITE,  IN_MODIFY|IN_CLOSE_WRITE },
	{ GENEV_ATTRIB, IN_ATTRIB },
	{ GENEV_DELETE, IN_DELETE|IN_MOVED_FROM },
	{ 0 }
};


static int ifd;

int
sysev_filemask(struct dirwatcher *dp)
{
	return 0;
}

void
sysev_init()
{
	ifd = inotify_init();
	if (ifd == -1) {
		diag(LOG_CRIT, "inotify_init: %s", strerror(errno));
		exit(1);
	}
}

int
sysev_add_watch(struct dirwatcher *dwp, event_mask mask)
{
	return inotify_add_watch(ifd, dwp->dirname, mask.sys_mask);
}

void
sysev_rm_watch(struct dirwatcher *dwp)
{
	inotify_rm_watch(ifd, dwp->wd);
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

static void
process_event(struct inotify_event *ep)
{
	struct dirwatcher *dp;
	struct handler *h;
	event_mask m;
	char *dirname, *filename;
	
	dp = dirwatcher_lookup_wd(ep->wd);
	if (ep->mask & IN_IGNORED)
		return;
	else if (ep->mask & IN_Q_OVERFLOW) {
		diag(LOG_NOTICE,
		     "event queue overflow");
		return;
	} else if (ep->mask & IN_UNMOUNT) {
		/* FIXME: not sure if there's
		   anything to do. Perhaps we should
		   deregister the watched dirs that
		   were located under the mountpoint
		*/
		return;
	} else if (!dp) {
		if (ep->name)
			diag(LOG_NOTICE, "unrecognized event %x"
			     "for %s", ep->mask, ep->name);
		else
			diag(LOG_NOTICE,
			     "unrecognized event %x", ep->mask);
		return;
	}

	ev_log(ep->mask, dp);

	if (ep->mask & IN_CREATE) {
		debug(1, ("%s/%s created", dp->dirname, ep->name));
		if (check_new_watcher(dp->dirname, ep->name) > 0)
			return;
	} else if (ep->mask & (IN_DELETE|IN_MOVED_FROM)) {
		debug(1, ("%s/%s deleted", dp->dirname, ep->name));
		remove_watcher(dp->dirname, ep->name);
	}

	if (ep->len == 0)
		filename = split_pathname(dp, &dirname);
	else {
		dirname = dp->dirname;
		filename = ep->name;
	}
	for (h = dp->handler_list; h; h = h->next) {
		if (handler_matches_event(h, sys, ep->mask, filename))
			run_handler(h, event_mask_init(&m,
						       ep->mask,
						       &h->ev_mask),
				    dirname, filename);
	}
	unsplit_pathname(dp);
}	

int
sysev_select()
{
	char buffer[4096];
	struct inotify_event *ep;
	size_t size;
	ssize_t rdbytes;

	rdbytes = read(ifd, buffer, sizeof(buffer));
	if (rdbytes == -1) {
		if (errno == EINTR) {
			if (signo == SIGCHLD || signo == SIGALRM)
				return 0;
			diag(LOG_NOTICE, "got signal %d", signo);
			return 1;
		}
		
		diag(LOG_NOTICE, "read failed: %s", strerror(errno));
		return 1;
	}
		
	ep = (struct inotify_event *) buffer;
	while (rdbytes) {
		if (ep->wd >= 0)
			process_event(ep);
		size = sizeof(*ep) + ep->len;
		ep = (struct inotify_event *) ((char*) ep + size);
		rdbytes -= size;
	}
	
	return 0;
}
