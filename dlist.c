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
