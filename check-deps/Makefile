CHECK_LIST := clock_without_librt
CHECK_LIST += cc_has_mfentry
CHECK_LIST += cxa_demangle

#
# This is needed for checking build dependency
#

CHECK_CFLAGS  = $(CFLAGS)  $(CFLAGS_$@)
CHECK_LDFLAGS = $(LDFLAGS) $(LDFLAGS_$@)

CFLAGS_cc_has_mfentry = -mfentry
LDFLAGS_cxa_demangle = -lstdc++

check-build: check-tstamp $(CHECK_LIST)

$(CHECK_LIST): %: __%.c
	@$(CC) $(CHECK_CFLAGS) -o $@ $< $(CHECK_LDFLAGS) > /dev/null 2>&1

check-tstamp: PHONY
	@touch $@

check-clean:
	@$(RM) $(CHECK_LIST) check-tstamp *.o

.PHONY: PHONY;
