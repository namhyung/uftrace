TEST_CFLAGS  := -D_GNU_SOURCE -DUNIT_TEST -I$(srcdir) -I$(objdir)
TEST_CFLAGS  += -include $(srcdir)/tests/unittest.h
TEST_LDFLAGS := -L$(objdir)/libtraceevent -ltraceevent -lelf -pthread -lrt -ldl

UNIT_TEST_SRC := $(wildcard $(srcdir)/*.c $(srcdir)/utils/*.c)

test: test_unit test_run

test_run:
	./runtest.py $(TESTARG)

test_unit: unittest
	./unittest $(filter -d,$(TESTARG))

unittest: unittest.c unittest.h $(UNIT_TEST_SRC)
	@$(CC) -o $@ $(TEST_CFLAGS) $(filter-out %.h,$^) $(TEST_LDFLAGS)

clean:
	@rm -f *.o *.so *.pyc t-* unittest

.PHONY: clean test test_run test_unit unittest
