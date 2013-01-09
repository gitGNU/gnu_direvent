/* General-purpose doubly-linked lists for dircond.
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

struct LIST *
LIST_UNLINK(struct LIST **root, struct LIST *p)
{
	if (p->prev)
		p->prev->next = p->next;
	else
		*root = p->next;
	if (p->next)
		p->next->prev = p->prev;
	p->next = p->prev = NULL;
	return p;
}

struct LIST *
LIST_POP(struct LIST **pp)
{
	if (*pp)
		return LIST_UNLINK(pp, *pp);
	return NULL;
}

void
LIST_PUSH(struct LIST **pp, struct LIST *p)
{
	p->prev = NULL;
	p->next = *pp;
	if (*pp)
		(*pp)->prev = p;
	*pp = p;
}

#undef LIST
#undef LIST_PUSH
#undef LIST_POP
#undef LIST_UNLINK
