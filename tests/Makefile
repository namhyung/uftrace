TEST_CFLAGS  += -include $(srcdir)/tests/unittest.h -Wno-sign-compare
TEST_CFLAGS  += -pg -g

UNIT_TEST_SRC := $(srcdir)/uftrace.c
UNIT_TEST_SRC += $(wildcard $(srcdir)/cmds/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/utils/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/arch/$(ARCH)/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/libmcount/*.c)
UNIT_TEST_OBJ := $(patsubst %.c,%.ot,$(UNIT_TEST_SRC))
UNIT_TEST_OBJ := $(filter-out %-nop.ot,$(UNIT_TEST_OBJ))

FULL_WORKER := -j $(shell getconf _NPROCESSORS_ONLN || echo 1)

# these needs to be recursively expanded
JOPT = $(filter -j%, $(MAKEFLAGS))
WORKER = $(if $(JOPT), $(if $(patsubst -j%,%,$(JOPT)), $(JOPT), $(FULL_WORKER)), -j1)

include $(srcdir)/Makefile.include

test: test_unit test_run

test_run:
	./runtest.py $(WORKER) $(TESTARG)

test_unit: unittest
	./unittest $(TESTARG)

unittest: unittest.c unittest.h $(UNIT_TEST_OBJ)
	$(QUIET_LINK)$(CC) -o $@ $(TEST_CFLAGS) $< $(UNIT_TEST_OBJ) $(TEST_LDFLAGS)

$(UNIT_TEST_OBJ): %.ot: %.c $(srcdir)/version.h
	$(QUIET_CC)$(CC) -o $@ -c $(TEST_CFLAGS) $<

clean:
	$(call QUIET_CLEAN, test)
	@rm -f *.o *.so *.pyc t-* unittest $(UNIT_TEST_OBJ)

.PHONY: clean test test_run test_unit
