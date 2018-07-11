TEST_CFLAGS  += -include $(srcdir)/tests/unittest.h -Wno-sign-compare

UNIT_TEST_SRC := $(srcdir)/uftrace.c
UNIT_TEST_SRC += $(wildcard $(srcdir)/cmds/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/utils/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/arch/$(ARCH)/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/libmcount/*.c)
UNIT_TEST_OBJ := $(patsubst %.c,%.ot,$(UNIT_TEST_SRC))
UNIT_TEST_OBJ := $(filter-out %-nop.ot,$(UNIT_TEST_OBJ))

include $(srcdir)/Makefile.include

test: test_unit test_run

test_run:
	./runtest.py $(TESTARG)

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
