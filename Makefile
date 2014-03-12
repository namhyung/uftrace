CC = $(CROSS_COMPILE)gcc
RM = rm -f
INSTALL = install

COMMON_CFLAGS := -O2 -g -D_GNU_SOURCE $(EXTRA_CFLAGS)
#CFLAGS-DEBUG = -g -D_GNU_SOURCE $(CFLAGS_$@)
COMMON_LDFLAGS := -lelf -lrt $(EXTRA_LDFLAGS)

COMMON_CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

#
# Note that the plain CFLAGS and LDFLAGS can be changed
# by config/Makefile later but LIB_*FLAGS are not.
#
CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@)
LIB_CFLAGS = $(COMMON_CFLAGS) $(CFLAGS_$@) -fPIC -fvisibility=hidden

LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@)
LIB_LDFLAGS = $(COMMON_LDFLAGS) $(LDFLAGS_$@) -pthread

prefix ?= /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib

all:

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

CFLAGS_mcount.op = -pthread
CFLAGS_ftrace = -DINSTALL_LIB_PATH='"$(libdir)"'

include config/Makefile


TARGETS = libmcount.so libcygprof.so ftrace

FTRACE_SRCS = ftrace.c symbol.c rbtree.c info.c debug.c arch/$(ARCH)/cpuinfo.c
FTRACE_OBJS = $(FTRACE_SRCS:.c=.o)

LIBMCOUNT_SRCS = mcount.c symbol.c debug.c
LIBMCOUNT_OBJS = $(LIBMCOUNT_SRCS:.c=.op)

LIBCYGPROF_SRCS = mcount.c symbol.c debug.c cygprofile.c
LIBCYGPROF_OBJS = $(LIBCYGPROF_SRCS:.c=.op)

MAKEFLAGS = --no-print-directory


all: $(TARGETS)

$(LIBMCOUNT_OBJS): %.op: %.c mcount.h symbol.h utils.h
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

cygprofile.op: cygprofile.c mcount.h utils.h
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

arch/$(ARCH)/%.op: arch/$(ARCH)/*.S
	@$(MAKE) -C arch/$(ARCH) $(notdir $@)

libmcount.so: $(LIBMCOUNT_OBJS) arch/$(ARCH)/entry.op
	$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

libcygprof.so: $(LIBCYGPROF_OBJS) arch/$(ARCH)/plthook.op
	$(CC) -shared -o $@ $^ $(LIB_LDFLAGS)

ftrace: $(FTRACE_SRCS) mcount.h symbol.h utils.h rbtree.h
	$(CC) $(CFLAGS) -o $@ $(FTRACE_SRCS) $(LDFLAGS)

install: all
	@$(INSTALL) -d -m 755 $(DESTDIR)$(bindir)
	@$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
	@$(INSTALL) ftrace         $(DESTDIR)$(bindir)/ftrace
	@$(INSTALL) libmcount.so   $(DESTDIR)$(libdir)/libmcount.so
	@$(INSTALL) libcygprof.so  $(DESTDIR)$(libdir)/libcygprof.so

test: all
	@$(MAKE) -C tests ARCH=$(ARCH) test

clean:
	@$(RM) *.o *.op $(TARGETS) ftrace.data* gmon.out
	@$(MAKE) -sC arch/$(ARCH) clean
	@$(MAKE) -sC tests ARCH=$(ARCH) clean
	@$(MAKE) -sC config check-clean BUILD_FEATURE_CHECKS=0

.PHONY: all clean test PHONY
