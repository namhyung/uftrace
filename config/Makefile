CHECK_LIST  = clock_without_librt libiberty libiberty_demangle cxa_demangle
CHECK_LIST += cc_has_mfentry

ifndef BUILD_FEATURE_CHECKS

  ifeq ($(wildcard config/check-tstamp),)
    $(shell make -si -C config check-build BUILD_FEATURE_CHECKS=1)
  endif

  ifeq ($(wildcard config/clock_without_librt),)
    LDFLAGS_libmcount.so += -lrt
    LDFLAGS_libcygprof.so += -lrt
  endif

  ifneq ($(wildcard config/libiberty),)
    COMMON_CFLAGS += -DHAVE_LIBIBERTY
    COMMON_LDFLAGS += -liberty
    ifneq ($(wildcard config/libiberty_demangle),)
      COMMON_CFLAGS += -DHAVE_LIBIBERTY_DEMANGLE
    endif
  endif

  ifneq ($(wildcard config/cxa_demangle),)
    ifeq ($(wildcard config/libiberty_demangle),)
      COMMON_CFLAGS += -DHAVE_CXA_DEMANGLE
      COMMON_LDFLAGS += -lstdc++
    endif
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

LDFLAGS_libiberty = -liberty
LDFLAGS_libiberty_demangle = -liberty
LDFLAGS_cxa_demangle = -lstdc++

check-build: check-tstamp $(CHECK_LIST)

$(CHECK_LIST): %: check-%.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) > /dev/null 2>&1

check-tstamp: PHONY
	@touch $@

.PHONY: PHONY;

endif # BUILD_FEATURE_CHECKS

check-clean:
	@$(RM) $(CHECK_LIST) check-tstamp *.o
