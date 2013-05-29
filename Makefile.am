ACLOCAL_AMFLAGS = -I grecs/am

SUBDIRS=grecs src doc

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                   \
		git log --pretty='format:%ct  %an  <%ae>%n%n%s%n%n%b%n' |  \
		awk -f $(top_builddir)/grecs/build-aux/git2chg.awk > ChangeLog; \
        fi

