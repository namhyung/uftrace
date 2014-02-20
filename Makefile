CC = gcc
RM = rm -f

ASFLAGS = -g -D_GNU_SOURCE $(ASFLAGS_$@)
CFLAGS = -O2 -g -D_GNU_SOURCE $(CFLAGS_$@)
#CFLAGS-DEBUG = -g -D_GNU_SOURCE $(CFLAGS_$@)
LDFLAGS = -lelf $(LDFLAGS_$@)

CFLAGS += -W -Wall -Wno-unused-parameter -Wno-missing-field-initializers

all:

uname_M := $(shell uname -m 2>/dev/null || echo not)

ARCH ?= $(shell echo $(uname_M) | sed -e s/i.86/i386/ -e s/arm.*/arm/ )
ifeq ($(ARCH),x86_64)
  ifneq ($(findstring m32,$(CFLAGS)),)
    override ARCH := i386
  endif
endif

CFLAGS_mcount.op = -fPIC -fvisibility=hidden -pthread
CFLAGS_symbol.op = -fPIC -fvisibility=hidden
CFLAGS_cygprofile.op = -fPIC

LDFLAGS_libmcount.so = -pthread
LDFLAGS_libcygprof.so = -pthread

include config/Makefile


TARGETS = libmcount.so libcygprof.so ftrace

FTRACE_SRCS = ftrace.c symbol.c rbtree.c info.c arch/$(ARCH)/cpuinfo.c
FTRACE_OBJS = $(FTRACE_SRCS:.c=.o)

LIBMCOUNT_SRCS = mcount.c symbol.c
LIBMCOUNT_OBJS = $(LIBMCOUNT_SRCS:.c=.op)

LIBCYGPROF_SRCS = mcount.c symbol.c cygprofile.c
LIBCYGPROF_OBJS = $(LIBCYGPROF_SRCS:.c=.op)

MAKEFLAGS = --no-print-directory


all: $(TARGETS)

$(LIBMCOUNT_OBJS): %.op: %.c mcount.h symbol.h
	$(CC) $(CFLAGS) -c -o $@ $<

cygprofile.op: cygprofile.c mcount.h
	$(CC) $(CFLAGS) -c -o $@ $<

arch/$(ARCH)/%.op: PHONY
	@$(MAKE) -C arch/$(ARCH) $(notdir $@)

libmcount.so: $(LIBMCOUNT_OBJS) arch/$(ARCH)/entry.op
	$(CC) -shared -o $@ $^ $(LDFLAGS)

libcygprof.so: $(LIBCYGPROF_OBJS) arch/$(ARCH)/plthook.op
	$(CC) -shared -o $@ $^ $(LDFLAGS)

ftrace: $(FTRACE_SRCS) mcount.h symbol.h utils.h rbtree.h
	$(CC) $(CFLAGS) -o $@ $(FTRACE_SRCS) $(LDFLAGS)

test: all
	@$(MAKE) -C tests ARCH=$(ARCH) test

clean:
	@$(RM) *.o *.op $(TARGETS) ftrace.data* gmon.out
	@$(MAKE) -sC arch/$(ARCH) clean
	@$(MAKE) -sC tests ARCH=$(ARCH) clean
	@$(MAKE) -sC config check-clean BUILD_FEATURE_CHECKS=0

.PHONY: all clean test PHONY
