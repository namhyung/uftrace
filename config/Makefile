CHECK_LIST  = clock_without_librt cc_has_mfentry

ifndef BUILD_FEATURE_CHECKS

  ifeq ($(wildcard config/check-tstamp),)
    $(shell make -si -C config check-build BUILD_FEATURE_CHECKS=1)
  endif

  ifeq ($(wildcard config/clock_without_librt),)
    LDFLAGS_libmcount.so += -lrt
    LDFLAGS_libcygprof.so += -lrt
  endif

  ifneq ($(wildcard config/cc_has_mfentry),)
    export HAVE_CC_MFENTRY = 1
  endif

else # BUILD_FEATURE_CHECKS

#
# This is needed for build config tests
#

CC = $(CROSS_COMPILE)gcc
RM = rm -f

CFLAGS = $(CFLAGS_$@)
LDFLAGS = $(LDFLAGS_$@)

CFLAGS_cc_has_mfentry = -mfentry

check-build: check-tstamp $(CHECK_LIST)

$(CHECK_LIST): %: check-%.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) > /dev/null 2>&1

check-tstamp: PHONY
	@touch $@

.PHONY: PHONY;

endif # BUILD_FEATURE_CHECKS

check-clean:
	@$(RM) $(CHECK_LIST) check-tstamp *.o
