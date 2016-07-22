VERSION := 0.5

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR and LD, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

prefix ?= /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib
mandir = $(prefix)/share/man

srcdir = $(CURDIR)
# set objdir to $(O) by default (if any)
ifeq ($(objdir),)
    ifneq ($(O),)
        objdir = $(O)
    else
        objdir = $(CURDIR)
    endif
endif

ifneq ($(wildcard $(objdir)/.config),)
  include $(objdir)/.config
endif

RM = rm -f
INSTALL = install

export ARCH CC AR LD RM srcdir objdir

COMMON_CFLAGS := -O2 -g -D_GNU_SOURCE $(CFLAGS)
COMMON_CFLAGS +=  -iquote $(srcdir) -iquote $(objdir) -iquote $(srcdir)/arch/$(ARCH)
#CFLAGS-DEBUG = -g -D_GNU_SOURCE $(CFLAGS_$@)
COMMON_LDFLAGS := -lelf -lrt -pthread $(LDFLAGS)

COMMON_CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but LIB_*FLAGS are not.
#
UFTRACE_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@)
LIB_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) -fPIC -fvisibility=hidden

UFTRACE_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)
LIB_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)

VERSION_GIT := $(shell git describe --tags 2> /dev/null || echo v$(VERSION))

all:

include $(srcdir)/config/Makefile
include $(srcdir)/config/Makefile.include


LIBMCOUNT_TARGETS := libmcount/libmcount.so libmcount/libmcount-fast.so
LIBMCOUNT_TARGETS += libmcount/libmcount-single.so libmcount/libmcount-fast-single.so

_TARGETS := uftrace libtraceevent/libtraceevent.a
_TARGETS += $(LIBMCOUNT_TARGETS) libmcount/libmcount-nop.so
TARGETS  := $(patsubst %,$(objdir)/%,$(_TARGETS))

UFTRACE_SRCS := $(srcdir)/uftrace.c $(wildcard $(srcdir)/cmd-*.c $(srcdir)/utils/*.c)
UFTRACE_SRCS += $(wildcard $(srcdir)/arch/$(ARCH)/cpuinfo.c)
UFTRACE_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.o,$(UFTRACE_SRCS))

UFTRACE_HDRS := $(wildcard $(srcdir)/*.h $(srcdir)/utils/*.h)
UFTRACE_HDRS += $(srcdir)/libmcount/mcount.h

LIBMCOUNT_SRCS := $(filter-out %-nop.c,$(wildcard $(srcdir)/libmcount/*.c))
LIBMCOUNT_SRCS += $(srcdir)/utils/symbol.c $(srcdir)/utils/debug.c
LIBMCOUNT_SRCS += $(srcdir)/utils/rbtree.c $(srcdir)/utils/filter.c
LIBMCOUNT_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
LIBMCOUNT_SRCS += $(wildcard $(srcdir)/arch/$(ARCH)/mcount-support.c)
LIBMCOUNT_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_SRCS))

LIBMCOUNT_HDRS := $(srcdir)/libmcount/mcount.h $(wildcard $(srcdir)/utils/*.h)

LIBMCOUNT_NOP_SRCS := $(srcdir)/libmcount/mcount-nop.c
LIBMCOUNT_NOP_OBJS := $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_NOP_SRCS))

LIBMCOUNT_FAST_SRCS := $(srcdir)/utils/symbol.c $(srcdir)/utils/debug.c
LIBMCOUNT_FAST_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
LIBMCOUNT_FAST_SRCS += $(srcdir)/utils/rbtree.c
LIBMCOUNT_FAST_SRCS += $(wildcard $(srcdir)/arch/$(ARCH)/mcount-support.c)
LIBMCOUNT_FAST_OBJS := $(objdir)/libmcount/mcount-fast.op
LIBMCOUNT_FAST_OBJS += $(objdir)/libmcount/plthook-fast.op
LIBMCOUNT_FAST_OBJS += $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_FAST_SRCS))

LIBMCOUNT_SINGLE_SRCS := $(srcdir)/utils/symbol.c $(srcdir)/utils/debug.c
LIBMCOUNT_SINGLE_SRCS += $(srcdir)/utils/rbtree.c $(srcdir)/utils/filter.c
LIBMCOUNT_SINGLE_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
LIBMCOUNT_SINGLE_SRCS += $(wildcard $(srcdir)/arch/$(ARCH)/mcount-support.c)
LIBMCOUNT_SINGLE_OBJS := $(objdir)/libmcount/mcount-single.op
LIBMCOUNT_SINGLE_OBJS += $(objdir)/libmcount/plthook-single.op
LIBMCOUNT_SINGLE_OBJS += $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_SINGLE_SRCS))

LIBMCOUNT_FAST_SINGLE_SRCS := $(srcdir)/utils/symbol.c $(srcdir)/utils/debug.c
LIBMCOUNT_FAST_SINGLE_SRCS += $(srcdir)/utils/demangle.c $(srcdir)/utils/utils.c
LIBMCOUNT_FAST_SINGLE_SRCS += $(srcdir)/utils/rbtree.c
LIBMCOUNT_FAST_SINGLE_SRCS += $(wildcard $(srcdir)/arch/$(ARCH)/mcount-support.c)
LIBMCOUNT_FAST_SINGLE_OBJS := $(objdir)/libmcount/mcount-fast-single.op
LIBMCOUNT_FAST_SINGLE_OBJS += $(objdir)/libmcount/plthook-fast-single.op
LIBMCOUNT_FAST_SINGLE_OBJS += $(patsubst $(srcdir)/%.c,$(objdir)/%.op,$(LIBMCOUNT_FAST_SINGLE_SRCS))

LIBMCOUNT_MCOUNT_OBJS := $(patsubst libmcount/lib%.so,$(objdir)/libmcount/%.op,$(LIBMCOUNT_TARGETS))
LIBMCOUNT_PLTHOOK_OBJS := $(patsubst libmcount/libmcount%.so,$(objdir)/libmcount/plthook%.op,$(LIBMCOUNT_TARGETS))

LIBMCOUNT_COMMON_OBJS := $(filter-out $(objdir)/libmcount/mcount.op,$(LIBMCOUNT_OBJS))
LIBMCOUNT_COMMON_OBJS := $(filter-out $(objdir)/libmcount/plthook.op,$(LIBMCOUNT_COMMON_OBJS))

CFLAGS_$(objdir)/mcount.op = -pthread
CFLAGS_$(objdir)/uftrace.o = -DINSTALL_LIB_PATH='"$(libdir)"'
LDFLAGS_$(objdir)/uftrace = -L$(objdir)/libtraceevent -ltraceevent -ldl

CFLAGS_$(objdir)/libmcount/mcount-fast.op = -DDISABLE_MCOUNT_FILTER
CFLAGS_$(objdir)/libmcount/plthook-fast.op = -DDISABLE_MCOUNT_FILTER
CFLAGS_$(objdir)/libmcount/mcount-single.op = -DSINGLE_THREAD
CFLAGS_$(objdir)/libmcount/plthook-single.op = -DSINGLE_THREAD
CFLAGS_$(objdir)/libmcount/mcount-fast-single.op = -DDISABLE_MCOUNT_FILTER -DSINGLE_THREAD
CFLAGS_$(objdir)/libmcount/plthook-fast-single.op = -DDISABLE_MCOUNT_FILTER -DSINGLE_THREAD

CFLAGS_$(objdir)/utils/demangle.o  = -Wno-unused-value
CFLAGS_$(objdir)/utils/demangle.op = -Wno-unused-value

MAKEFLAGS = --no-print-directory


all: $(objdir)/.config $(TARGETS)

$(objdir)/.config: $(srcdir)/configure
	$(QUIET_GEN)$(srcdir)/configure -o $@ $(MAKEOVERRIDES)

config: $(srcdir)/configure
	$(QUIET_GEN)$(srcdir)/configure -o $(objdir)/.config $(MAKEOVERRIDES)

$(LIBMCOUNT_COMMON_OBJS): $(objdir)/%.op: $(srcdir)/%.c $(LIBMCOUNT_HDRS) $(objdir)/.config
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(LIBMCOUNT_MCOUNT_OBJS): $(objdir)/%.op: $(srcdir)/libmcount/mcount.c $(objdir)/.config
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(LIBMCOUNT_PLTHOOK_OBJS): $(objdir)/%.op: $(srcdir)/libmcount/plthook.c $(objdir)/.config
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(objdir)/libmcount/mcount-nop.op: $(srcdir)/libmcount/mcount-nop.c $(objdir)/.config
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(objdir)/arch/$(ARCH)/entry.op: $(wildcard $(srcdir)/arch/$(ARCH)/*.[cS]) $(objdir)/.config
	@$(MAKE) -B -C $(srcdir)/arch/$(ARCH) $@

$(objdir)/libmcount/libmcount.so: $(LIBMCOUNT_OBJS) $(objdir)/arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-nop.so: $(LIBMCOUNT_NOP_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-fast.so: $(LIBMCOUNT_FAST_OBJS) $(objdir)/arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-single.so: $(LIBMCOUNT_SINGLE_OBJS) $(objdir)/arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libmcount/libmcount-fast-single.so: $(LIBMCOUNT_FAST_SINGLE_OBJS) $(objdir)/arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

$(objdir)/libtraceevent/libtraceevent.a: PHONY
	@$(MAKE) -C $(srcdir)/libtraceevent BUILD_SRC=$(srcdir)/libtraceevent BUILD_OUTPUT=$(objdir)/libtraceevent

$(objdir)/uftrace.o: $(srcdir)/uftrace.c $(objdir)/version.h $(UFTRACE_HDRS) $(objdir)/.config
	$(QUIET_CC)$(CC) $(UFTRACE_CFLAGS) -c -o $@ $<

$(filter-out $(objdir)/uftrace.o,$(UFTRACE_OBJS)): $(objdir)/%.o: $(srcdir)/%.c $(UFTRACE_HDRS) $(objdir)/.config
	$(QUIET_CC)$(CC) $(UFTRACE_CFLAGS) -c -o $@ $<

$(objdir)/version.h: PHONY
	@$(srcdir)/misc/version.sh $(objdir)/version.h $(VERSION_GIT)

$(objdir)/uftrace: $(UFTRACE_OBJS) $(objdir)/libtraceevent/libtraceevent.a
	$(QUIET_LINK)$(CC) $(UFTRACE_CFLAGS) -o $@ $(UFTRACE_OBJS) $(UFTRACE_LDFLAGS)

install: all
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(call QUIET_INSTALL, uftrace)
	$(Q)$(INSTALL) $(objdir)/uftrace         $(DESTDIR)$(bindir)/uftrace
	$(call QUIET_INSTALL, libmcount)
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount.so   $(DESTDIR)$(libdir)/libmcount.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-nop.so $(DESTDIR)$(libdir)/libmcount-nop.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-fast.so $(DESTDIR)$(libdir)/libmcount-fast.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-single.so $(DESTDIR)$(libdir)/libmcount-single.so
	$(Q)$(INSTALL) $(objdir)/libmcount/libmcount-fast-single.so $(DESTDIR)$(libdir)/libmcount-fast-single.so
	@$(MAKE) -sC $(srcdir)/doc install DESTDIR=$(DESTDIR)$(mandir)
	@if [ `id -u` = 0 ]; then ldconfig $(DESTDIR)$(libdir) || echo "ldconfig failed"; fi

uninstall:
	$(call QUIET_UNINSTALL, uftrace)
	$(Q)$(RM) $(DESTDIR)$(bindir)/uftrace
	$(call QUIET_UNINSTALL, libmcount)
	$(Q)$(RM) $(DESTDIR)$(libdir)/libmcount{,-nop,-fast,-single,-fast-single}.so
	@$(MAKE) -sC $(srcdir)/doc uninstall DESTDIR=$(DESTDIR)$(mandir)

test: all
	@$(MAKE) -C $(srcdir)/tests TESTARG="$(TESTARG)" test

dist:
	@git archive --prefix=uftrace-$(VERSION)/ $(VERSION_GIT) -o $(objdir)/uftrace-$(VERSION).tar
	@tar rf $(objdir)/uftrace-$(VERSION).tar --transform="s|^|uftrace-$(VERSION)/|" $(objdir)/version.h
	@gzip $(objdir)/uftrace-$(VERSION).tar

doc:
	@$(MAKE) -C $(srcdir)/doc

clean:
	$(call QUIET_CLEAN, uftrace)
	$(Q)$(RM) $(objdir)/*.o $(objdir)/*.op $(objdir)/*.so $(objdir)/*.a
	$(Q)$(RM) $(objdir)/utils/*.o $(objdir)/utils/*.op $(objdir)/libmcount/*.op
	$(Q)$(RM) $(objdir)/uftrace.data* $(objdir)/gmon.out $(TARGETS)
	$(Q)$(RM) $(objdir)/uftrace-*.tar.gz $(objdir)/version.h
	@$(MAKE) -sC $(srcdir)/arch/$(ARCH) clean
	@$(MAKE) -sC $(srcdir)/tests ARCH=$(ARCH) clean
	@$(MAKE) -sC $(srcdir)/config check-clean BUILD_FEATURE_CHECKS=0
	@$(MAKE) -sC $(srcdir)/doc clean
	@$(MAKE) -sC $(srcdir)/libtraceevent clean

.PHONY: all config clean test dist doc PHONY
