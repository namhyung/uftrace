CC = gcc
CXX = g++
RM = rm -f
FTRACE = ../ftrace -L .. --flat -b 4096

CFLAGS = -g -pg
#CFLAGS = -g -finstrument-functions
LDFLAGS = -pthread

#ifeq ($(ARCH),arm)
CFLAGS += -fno-omit-frame-pointer
#endif

TARGETS = t-abc t-threaded-abc t-arg t-demangle t-local t-abcd t-fork t-spawn

TARGETS_O1 = $(patsubst %,%_O1,$(TARGETS))
TARGETS_O2 = $(patsubst %,%_O2,$(TARGETS))
TARGETS_O3 = $(patsubst %,%_O3,$(TARGETS))
TARGETS_Os = $(patsubst %,%_Os,$(TARGETS))

ALL_TARGETS = $(TARGETS) $(TARGETS_O1) $(TARGETS_O2) $(TARGETS_O3) $(TARGETS_Os)
MAKEFLAGS = --no-print-directory

all: $(ALL_TARGETS)

t-%: %.c
	$(CC) $(CFLAGS) -o $@ $< -pthread

t-%_O1: %.c
	$(CC) $(CFLAGS) -O1 -o $@ $< -pthread

t-%_O2: %.c
	$(CC) $(CFLAGS) -O2 -o $@ $< -pthread

t-%_O3: %.c
	$(CC) $(CFLAGS) -O3 -o $@ $< -pthread

t-%_Os: %.c
	$(CC) $(CFLAGS) -Os -o $@ $< -pthread

t-%: %.cpp
	$(CXX) $(CFLAGS) -o $@ $<

t-%_O1: %.cpp
	$(CXX) $(CFLAGS) -O1 -o $@ $<

t-%_O2: %.cpp
	$(CXX) $(CFLAGS) -O2 -o $@ $<

t-%_O3: %.cpp
	$(CXX) $(CFLAGS) -O3 -o $@ $<

t-%_Os: %.cpp
	$(CXX) $(CFLAGS) -Os -o $@ $<

RED   = '\033[01;31m'
GREEN = '\033[01;32m'
RESET = '\033[00m'

export RED GREEN RESET

test_run = $(FTRACE) $(1) 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | sed -e 's/<[0-9a-f]\+>/<unknown>/'
test_and_diff = printf "%20s: " $(1); $(test_run) | diff -U0 $(2) - > $(1)-diff && \
		printf [${GREEN}OK${RESET}]"\n" || printf [${RED}NG${RESET}]"\n"

test: all
	@echo === generic tests ===
	@echo testing -O0
	@for t in $(TARGETS); do $(call test_run, $$t) > "$${t}_result"; done
	@echo testing -O1
	@for t in $(TARGETS_O1); do $(call test_and_diff, $$t, $${t%_O1}_result); done
	@echo testing -O2
	@for t in $(TARGETS_O2); do $(call test_and_diff, $$t, $${t%_O2}_result); done
	@echo testing -O3
	@for t in $(TARGETS_O3); do $(call test_and_diff, $$t, $${t%_O3}_result); done
	@echo testing -Os
	@for t in $(TARGETS_Os); do $(call test_and_diff, $$t, $${t%_Os}_result); done
ifdef ARCH
	@echo === arch specific tests ===
	@$(MAKE) -C arch/$(ARCH) test
endif

clean:
	$(RM) $(ALL_TARGETS) *.o ftrace.data* gmon.out *-diff
ifdef ARCH
	@$(MAKE) -C arch/$(ARCH) clean
endif

.PHONY: clean test arch
