TEST_CFLAGS  += -g -include $(srcdir)/tests/unittest.h -Wno-sign-compare $(CFLAGS_$@)
TEST_AFLAGS  := -iquote $(srcdir) -iquote $(objdir) -iquote $(srcdir)/arch/$(ARCH)
TEST_AFLAGS  += $(CFLAGS) $(CFLAGS_$@)

UNIT_TEST_SRC := $(srcdir)/uftrace.c
UNIT_TEST_SRC += $(wildcard $(srcdir)/cmds/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/utils/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/arch/$(ARCH)/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/libmcount/*.c)
ifneq ($(findstring HAVE_LIBPYTHON, $(TEST_CFLAGS)), )
UNIT_TEST_SRC += $(wildcard $(srcdir)/python/*.c)
endif
UNIT_TEST_OBJ := $(patsubst $(srcdir)/%.c,$(objdir)/%.ot,$(UNIT_TEST_SRC))
UNIT_TEST_OBJ := $(filter-out %-nop.ot,$(UNIT_TEST_OBJ))

UNIT_TEST_ASM := $(wildcard $(srcdir)/arch/$(ARCH)/*.S)
UNIT_TEST_AOB := $(patsubst $(srcdir)/%.S,$(objdir)/%.ot,$(UNIT_TEST_ASM))

UNIT_TEST_HDR := $(srcdir)/uftrace.h
UNIT_TEST_HDR += $(srcdir)/tests/unittest.h
UNIT_TEST_HDR += $(wildcard $(srcdir)/utils/*.h)
UNIT_TEST_HDR += $(wildcard $(srcdir)/arch/$(ARCH)/*.h)
UNIT_TEST_HDR += $(wildcard $(srcdir)/libmcount/*.h)

UNIT_TEST_OBJ_VERSION := $(objdir)/cmds/script.ot $(objdir)/cmds/tui.ot
UNIT_TEST_OBJ_VERSION += $(objdir)/cmds/dump.ot   $(objdir)/cmds/info.ot
UNIT_TEST_OBJ_VERSION += $(objdir)/libmcount/mcount.ot


FULL_WORKER := -j $(shell getconf _NPROCESSORS_ONLN || echo 1)

# these needs to be recursively expanded
JOPT = $(filter -j%, $(MAKEFLAGS))
WORKER = $(if $(JOPT), $(if $(patsubst -j%,%,$(JOPT)), $(JOPT), $(FULL_WORKER)), -j1)

include $(srcdir)/Makefile.include

test: test_all

test_all: unittest
	$(QUIET_TEST)./unittest $(TESTARG) $(UNITTESTARG)
	$(QUIET_TEST)./runtest.py $(WORKER) $(TESTARG) $(RUNTESTARG)
ifneq ($(findstring HAVE_LIBPYTHON, $(TEST_CFLAGS)), )
	$(QUIET_TEST)./runtest.py -P $(WORKER) $(TESTARG) $(PYTESTARG)
endif

test_run:
	$(QUIET_TEST)./runtest.py $(WORKER) $(TESTARG) $(RUNTESTARG)

test_python:
	$(QUIET_TEST)./runtest.py -P $(WORKER) $(TESTARG) $(PYTESTARG)

test_unit: unittest
	$(QUIET_TEST)./unittest $(TESTARG) $(UNITTESTARG)

unittest: unittest.c unittest.h $(UNIT_TEST_OBJ) $(UNIT_TEST_AOB)
	$(QUIET_LINK)$(CC) -o $@ $(TEST_CFLAGS) $(filter-out unittest.h, $^) $(TEST_LDFLAGS)

$(UNIT_TEST_OBJ_VERSION): $(objdir)/version.h

$(UNIT_TEST_OBJ): $(objdir)/%.ot: $(srcdir)/%.c $(objdir)/.config $(UNIT_TEST_HDR)
	$(QUIET_CC)$(CC) -o $@ -c $(TEST_CFLAGS) $<

$(UNIT_TEST_AOB): $(objdir)/%.ot: $(srcdir)/%.S $(objdir)/.config $(UNIT_TEST_HDR)
	$(QUIET_ASM)$(CC) -o $@ -c $(TEST_AFLAGS) $<

clean:
	$(call QUIET_CLEAN, test)
	@rm -f *.o *.so *.pyc t-* unittest $(UNIT_TEST_OBJ)

.PHONY: clean test test_run test_unit test_python
