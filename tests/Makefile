TEST_CFLAGS  := -D_GNU_SOURCE -DUNIT_TEST -I$(srcdir) -I$(objdir) -g
TEST_CFLAGS  += -include $(srcdir)/tests/unittest.h
TEST_LDFLAGS := -L$(objdir)/libtraceevent -ltraceevent -lelf -pthread -lrt -ldl

UNIT_TEST_SRC := $(wildcard $(srcdir)/*.c $(srcdir)/utils/*.c)
UNIT_TEST_SRC += $(wildcard $(srcdir)/arch/$(ARCH)/*.c)
UNIT_TEST_OBJ := $(patsubst %.c,%.ot,$(UNIT_TEST_SRC))

include $(srcdir)/Makefile.include

test: test_unit test_run

test_run:
	./runtest.py $(TESTARG)

test_unit: unittest
	./unittest $(TESTARG)

unittest: unittest.c unittest.h $(UNIT_TEST_OBJ)
	$(QUIET_LINK)$(CC) -o $@ $(TEST_CFLAGS) $< $(UNIT_TEST_OBJ) $(TEST_LDFLAGS)

$(UNIT_TEST_OBJ): %.ot: %.c
	$(QUIET_CC)$(CC) -o $@ -c $(TEST_CFLAGS) $^

clean:
	$(call QUIET_CLEAN, test)
	@rm -f *.o *.so *.pyc t-* unittest $(UNIT_TEST_OBJ)

.PHONY: clean test test_run test_unit
