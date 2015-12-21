TEST_CFLAGS  := -D_GNU_SOURCE -DUNIT_TEST -include unittest.h
TEST_LDFLAGS := ../libtraceevent/libtraceevent.a -lelf -pthread -lrt -ldl

UNIT_TEST_SRC := $(wildcard ../*.c ../utils/*.c)

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
