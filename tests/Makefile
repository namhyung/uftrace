CC = gcc
CXX = g++
RM = rm -f
FTRACE = ../ftrace

CFLAGS = -O0 -g -pg

TARGETS = t-abc t-threaded-abc t-arg t-demangle

MAKEFLAGS = --no-print-directory

all: $(TARGETS)

t-abc: abc.c
	$(CC) $(CFLAGS) -o $@ $<

t-threaded-abc: threaded-abc.c
	$(CC) $(CFLAGS) -o $@ $< -pthread

t-arg: arg.c
	$(CC) $(CFLAGS) -o $@ $<

t-demangle: demangle.cpp
	$(CXX) $(CFLAGS) -o $@ $<

test: all
	@for t in $(TARGETS); do $(FTRACE) -L .. $$t 1 2 3; done;
ifdef ARCH
	@$(MAKE) -C arch/$(ARCH) test
endif

clean:
	$(RM) $(TARGETS) *.o ftrace.data* gmon.out
ifdef ARCH
	@$(MAKE) -C arch/$(ARCH) clean
endif

.PHONY: clean test arch
