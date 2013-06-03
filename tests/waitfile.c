/* waitfile - wait until a file becomes available or a timeout expires
   This file is part of Dircond testsuite.
   Copyright (C) 2013 Sergey Poznyakoff

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

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	int ttl;
	struct timeval tv;
	time_t start;
	
	if (argc != 3) {
		fprintf(stderr, "usage: %s FILE TIMEOUT\n", argv[0]);
		return 1;
	}
	ttl = atoi(argv[2]);
	time(&start);
	while (access(argv[1], R_OK) && errno == ENOENT) {
		if (time(NULL) - start > ttl) {
			fprintf(stderr, "%s: timeout\n", argv[0]);
			return 1;
		}
		tv.tv_sec = 0;
		tv.tv_usec = 250000;
		select(0, NULL, NULL, NULL, &tv);
	}
	return 0;
}
