VERSION := 0.4

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

ifneq ($(wildcard .config),)
  include .config
endif

RM = rm -f
INSTALL = install

export ARCH CC AR LD RM

COMMON_CFLAGS := -O2 -g -D_GNU_SOURCE $(CFLAGS)
#CFLAGS-DEBUG = -g -D_GNU_SOURCE $(CFLAGS_$@)
COMMON_LDFLAGS := -lelf -lrt -pthread $(LDFLAGS)

COMMON_CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but LIB_*FLAGS are not.
#
FTRACE_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@)
LIB_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) -fPIC -fvisibility=hidden

FTRACE_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)
LIB_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)

VERSION_GIT := $(shell git describe --tags 2> /dev/null || echo v$(VERSION))

all:

include config/Makefile
include config/Makefile.include


TARGETS := ftrace libmcount/libmcount.so libmcount/libmcount-nop.so
TARGETS += libmcount/libmcount-fast.so libmcount/libmcount-single.so
TARGETS += libmcount/libmcount-fast-single.so libtraceevent/libtraceevent.a

FTRACE_SRCS  = ftrace.c cmd-record.c cmd-replay.c cmd-live.c cmd-report.c cmd-info.c
FTRACE_SRCS += cmd-recv.c
FTRACE_SRCS += utils/symbol.c utils/rbtree.c utils/debug.c
FTRACE_SRCS += utils/filter.c utils/kernel.c utils/utils.c utils/session.c
FTRACE_SRCS += utils/fstack.c utils/data-file.c utils/pager.c utils/demangle.c
FTRACE_SRCS += arch/$(ARCH)/cpuinfo.c
FTRACE_OBJS  = $(FTRACE_SRCS:.c=.o)
FTRACE_HDRS := ftrace.h libmcount/mcount.h utils/utils.h utils/filter.h
FTRACE_HDRS += utils/symbol.h utils/rbtree.h utils/list.h utils/fstack.h

LIBMCOUNT_SRCS  = $(filter-out %-nop.c,$(wildcard libmcount/*.c))
LIBMCOUNT_SRCS += utils/symbol.c utils/debug.c utils/rbtree.c utils/filter.c
LIBMCOUNT_SRCS += utils/demangle.c
LIBMCOUNT_OBJS  = $(LIBMCOUNT_SRCS:.c=.op)
LIBMCOUNT_HDRS  = libmcount/mcount.h utils/utils.h utils/symbol.h utils/filter.h
LIBMCOUNT_HDRS += utils/rbtree.h

LIBMCOUNT_NOP_SRCS = libmcount/mcount-nop.c
LIBMCOUNT_NOP_OBJS = $(LIBMCOUNT_NOP_SRCS:.c=.op)

LIBMCOUNT_FAST_SRCS = utils/symbol.c utils/debug.c utils/demangle.c
LIBMCOUNT_FAST_OBJS = $(LIBMCOUNT_FAST_SRCS:.c=.op) libmcount/mcount-fast.op

LIBMCOUNT_SINGLE_SRCS := utils/symbol.c utils/debug.c utils/rbtree.c utils/filter.c
LIBMCOUNT_SINGLE_SRCS += utils/demangle.c
LIBMCOUNT_SINGLE_OBJS = $(LIBMCOUNT_SINGLE_SRCS:.c=.op) libmcount/mcount-single.op

LIBMCOUNT_FAST_SINGLE_SRCS = utils/symbol.c utils/debug.c utils/demangle.c
LIBMCOUNT_FAST_SINGLE_OBJS = $(LIBMCOUNT_FAST_SINGLE_SRCS:.c=.op) libmcount/mcount-fast-single.op


CFLAGS_mcount.op = -pthread
CFLAGS_ftrace.o = -DINSTALL_LIB_PATH='"$(libdir)"' -I.
LDFLAGS_ftrace = libtraceevent/libtraceevent.a -ldl

CFLAGS_libmcount/mcount-fast.op = -DDISABLE_MCOUNT_FILTER
CFLAGS_libmcount/mcount-single.op = -DSINGLE_THREAD
CFLAGS_libmcount/mcount-fast-single.op = -DDISABLE_MCOUNT_FILTER -DSINGLE_THREAD

CFLAGS_utils/demangle.o  = -Wno-unused-value
CFLAGS_utils/demangle.op = -Wno-unused-value

MAKEFLAGS = --no-print-directory


all: .config $(TARGETS)

.config: configure
	$(QUIET_GEN)./configure $(MAKEOVERRIDES)

config: configure
	$(QUIET_GEN)./configure $(MAKEOVERRIDES)

$(LIBMCOUNT_OBJS): %.op: %.c $(LIBMCOUNT_HDRS) .config
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-nop.op: libmcount/mcount-nop.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-fast.op: libmcount/mcount.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-single.op: libmcount/mcount.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

libmcount/mcount-fast-single.op: libmcount/mcount.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

arch/$(ARCH)/entry.op: $(wildcard arch/$(ARCH)/*.[cS]) .config
	@$(MAKE) -B -C arch/$(ARCH) $(notdir $@)

libmcount/libmcount.so: $(LIBMCOUNT_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-nop.so: $(LIBMCOUNT_NOP_OBJS)
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-fast.so: $(LIBMCOUNT_FAST_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-single.so: $(LIBMCOUNT_SINGLE_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libmcount/libmcount-fast-single.so: $(LIBMCOUNT_FAST_SINGLE_OBJS) arch/$(ARCH)/entry.op
	$(QUIET_LINK)$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libtraceevent/libtraceevent.a: PHONY
	@$(MAKE) -sC libtraceevent

ftrace.o: ftrace.c version.h $(FTRACE_HDRS) .config
	$(QUIET_CC)$(CC) $(FTRACE_CFLAGS) -c -o $@ $<

$(filter-out ftrace.o,$(FTRACE_OBJS)): %.o: %.c $(FTRACE_HDRS) .config
	$(QUIET_CC)$(CC) $(FTRACE_CFLAGS) -c -o $@ $<

version.h: PHONY
	@misc/version.sh $(VERSION_GIT)

ftrace: $(FTRACE_OBJS) libtraceevent/libtraceevent.a
	$(QUIET_LINK)$(CC) $(FTRACE_CFLAGS) -o $@ $(FTRACE_OBJS) $(FTRACE_LDFLAGS)

install: all
	@$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	@$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	$(call QUIET_INSTALL, ftrace)
	@$(INSTALL) ftrace         $(DESTDIR)$(bindir)/ftrace
	$(call QUIET_INSTALL, libmcount.so)
	@$(INSTALL) libmcount/libmcount.so   $(DESTDIR)$(libdir)/libmcount.so
	$(call QUIET_INSTALL, libmcount-nop.so)
	@$(INSTALL) libmcount/libmcount-nop.so $(DESTDIR)$(libdir)/libmcount-nop.so
	$(call QUIET_INSTALL, libmcount-fast.so)
	@$(INSTALL) libmcount/libmcount-fast.so $(DESTDIR)$(libdir)/libmcount-fast.so
	$(call QUIET_INSTALL, libmcount-single.so)
	@$(INSTALL) libmcount/libmcount-single.so $(DESTDIR)$(libdir)/libmcount-single.so
	$(call QUIET_INSTALL, libmcount-fast-single.so)
	@$(INSTALL) libmcount/libmcount-fast-single.so $(DESTDIR)$(libdir)/libmcount-fast-single.so
	@$(MAKE) -sC doc install DESTDIR=$(DESTDIR)$(mandir)
	@if [ `id -u` = 0 ]; then ldconfig $(DESTDIR)$(libdir) || echo "ldconfig failed"; fi

test: all
	@$(MAKE) -C tests ARCH=$(ARCH) TESTARG="$(TESTARG)" test

dist:
	@git archive --prefix=ftrace-$(VERSION)/ $(VERSION_GIT) -o ftrace-$(VERSION).tar
	@tar rf ftrace-$(VERSION).tar --transform="s|^|ftrace-$(VERSION)/|" version.h
	@gzip ftrace-$(VERSION).tar

doc:
	@$(MAKE) -C doc

clean:
	$(call QUIET_CLEAN, ftrace)
	@$(RM) *.o *.op *.so utils/*.o utils/*.op libmcount/*.op
	@$(RM) ftrace.data* gmon.out FLAGS $(TARGETS)
	@$(RM) ftrace-*.tar.gz
	@$(MAKE) -sC arch/$(ARCH) clean
	@$(MAKE) -sC tests ARCH=$(ARCH) clean
	@$(MAKE) -sC config check-clean BUILD_FEATURE_CHECKS=0
	@$(MAKE) -sC doc clean
	@$(MAKE) -sC libtraceevent clean

.PHONY: all config clean test dist doc PHONY
