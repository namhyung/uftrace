TS_SH = ex1-test permute-test
TS_PROGS =

TS_ALL = $(TS_PROGS) $(TS_SH)

noinst_PROGRAMS = $(TS_PROGS) ex1 ex3 ex4

LDADD = ../libargp.a

EXTRA_DIST = $(TS_SH) run-tests
CLEANFILES = test.out

.PHONY: check 
check: $(TS_ALL) $(srcdir)/run-tests
	srcdir="$(srcdir)" $(srcdir)/run-tests $(TS_ALL)
