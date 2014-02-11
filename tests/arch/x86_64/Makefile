CC = gcc
RM = rm -f
FTRACE = ../../../ftrace -L ../../.. --flat

CFLAGS = -g -pg

TARGETS = t-fentry

TARGETS_O1 = $(patsubst %,%_O1,$(TARGETS))
TARGETS_O2 = $(patsubst %,%_O2,$(TARGETS))
TARGETS_O3 = $(patsubst %,%_O3,$(TARGETS))
TARGETS_Os = $(patsubst %,%_Os,$(TARGETS))

ALL_TARGETS = $(TARGETS) $(TARGETS_O1) $(TARGETS_O2) $(TARGETS_O3) $(TARGETS_Os)

all: $(ALL_TARGETS)

t-fentry: fentry.c
	$(CC) $(CFLAGS) -mfentry -o $@ $<

t-fentry_%: fentry.c
	$(CC) $(CFLAGS) -$(@:t-fentry_%=%) -mfentry -o $@ $<

test: all
	@echo testing -O0
	@for t in $(TARGETS); do \
		$(FTRACE) $$t | sort -k2 | cut -d/ -f2 | cut -d, -f1 > "$${t}_result"; \
	done;
	@echo testing -O1
	@for t in $(TARGETS_O1); do \
		$(FTRACE) $$t | sort -k2 | cut -d/ -f2 | cut -d, -f1 > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_O1}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
	@echo testing -O2
	@for t in $(TARGETS_O2); do \
		$(FTRACE) $$t | sort -k2 | cut -d/ -f2 | cut -d, -f1 > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_O2}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
	@echo testing -O3
	@for t in $(TARGETS_O3); do \
		$(FTRACE) $$t | sort -k2 | cut -d/ -f2 | cut -d, -f1 > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_O3}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;
	@echo testing -Os
	@for t in $(TARGETS_Os); do \
		$(FTRACE) $$t | sort -k2 | cut -d/ -f2 | cut -d, -f1 > tmp.result; \
		echo -n "  $${t}: "; diff -q "$${t%_Os}_result" tmp.result > /dev/null \
			&& echo OK || echo NG; \
		rm -f tmp.result; \
	done;

clean:
	$(RM) $(ALL_TARGETS) *.o ftrace.data* gmon.out

.PHONY: clean test arch
