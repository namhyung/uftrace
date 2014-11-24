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

TARGETS = t-abc t-threaded-abc t-arg t-demangle t-local t-abcd t-fork

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

test: all
	@echo === generic tests ===
	@echo testing -O0
	@for t in $(TARGETS); do \
		$(FTRACE) $$t 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | \
		sed -e 's/<[0-9a-f]\+>/<unknown>/' > "$${t}_result"; \
	done;
	@echo testing -O1
	@for t in $(TARGETS_O1); do \
		$(FTRACE) $$t 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | \
		sed -e 's/<[0-9a-f]\+>/<unknown>/' > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_O1}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
	@echo testing -O2
	@for t in $(TARGETS_O2); do \
		$(FTRACE) $$t 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | \
		sed -e 's/<[0-9a-f]\+>/<unknown>/' > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_O2}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
	@echo testing -O3
	@for t in $(TARGETS_O3); do \
		$(FTRACE) $$t 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | \
		sed -e 's/<[0-9a-f]\+>/<unknown>/' > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_O3}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
	@echo testing -Os
	@for t in $(TARGETS_Os); do \
		$(FTRACE) $$t 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | \
		sed -e 's/<[0-9a-f]\+>/<unknown>/' > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_Os}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
ifdef ARCH
	@echo === arch specific tests ===
	@$(MAKE) -C arch/$(ARCH) test
endif

clean:
	$(RM) $(ALL_TARGETS) *.o ftrace.data* gmon.out
ifdef ARCH
	@$(MAKE) -C arch/$(ARCH) clean
endif

.PHONY: clean test arch
