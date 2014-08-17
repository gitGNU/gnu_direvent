/* direvent - directory content watcher daemon
   Copyright (C) 2012-2014 Sergey Poznyakoff

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
#include <fnmatch.h>
#include <grecs.h>

void
filename_pattern_free(void *p)
{
	struct filename_pattern *pat = p;
	switch (pat->type) {
	case PAT_GLOB:
		free(pat->v.glob);
		break;
	case PAT_REGEX:
		regfree(&pat->v.re);
	}
	free(pat);
}

int
filename_pattern_match(struct grecs_list *lp, const char *name)
{
	struct grecs_list_entry *ep;

	if (!lp)
		return 0;
	for (ep = lp->head; ep; ep = ep->next) {
		struct filename_pattern *pat = ep->data;
		int rc;
		
		switch (pat->type) {
		case PAT_GLOB:
			rc = fnmatch(pat->v.glob, name, FNM_PATHNAME);
			break;
		case PAT_REGEX:
			rc = regexec(&pat->v.re, name, 0, NULL, 0);
			break;
		}
		if (pat->neg)
			rc = !rc;
		if (rc == 0)
			return 0;
	}
	return 1;
}
