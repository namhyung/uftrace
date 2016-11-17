CHECK_LIST  = clock_without_librt cc_has_mfentry cxa_demangle

#
# This is needed for build config tests
#

CFLAGS = $(CFLAGS_$@)
LDFLAGS = $(LDFLAGS_$@)

CFLAGS_cc_has_mfentry = -mfentry
LDFLAGS_cxa_demangle = -lstdc++

check-build: check-tstamp $(CHECK_LIST)

$(CHECK_LIST): %: check-%.c
	@$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) > /dev/null 2>&1

check-tstamp: PHONY
	@touch $@

check-clean:
	@$(RM) $(CHECK_LIST) check-tstamp *.o

.PHONY: PHONY;
