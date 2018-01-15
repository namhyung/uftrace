CC = gcc
RM = rm -f
UFTRACE = ../../../uftrace -L ../../.. --flat

CFLAGS = -g -finstrument-functions

TARGETS =

ifdef HAVE_CC_MFENTRY
TARGETS += t-fentry
endif

TARGETS_O1 = $(patsubst %,%_O1,$(TARGETS))
TARGETS_O2 = $(patsubst %,%_O2,$(TARGETS))
TARGETS_O3 = $(patsubst %,%_O3,$(TARGETS))
TARGETS_Os = $(patsubst %,%_Os,$(TARGETS))

ALL_TARGETS = $(TARGETS) $(TARGETS_O1) $(TARGETS_O2) $(TARGETS_O3) $(TARGETS_Os)

test_run = $(UFTRACE) $(1) 1 2 3 | sort -k2 | cut -d/ -f2 | cut -d, -f1 | sed -e 's/<[0-9a-f]\+>/<unknown>/'
test_and_diff = printf "%20s: " $(1); $(test_run) | diff -U0 $(2) - > $(1)-diff && \
		printf [${GREEN}OK${RESET}]"\n" || printf [${RED}NG${RESET}]"\n"

all: $(ALL_TARGETS)

t-fentry: fentry.c
	$(CC) $(CFLAGS) -mfentry -o $@ $<

t-fentry_%: fentry.c
	$(CC) $(CFLAGS) -$(@:t-fentry_%=%) -mfentry -o $@ $<

test: all
	@echo testing -O0
	@for t in $(TARGETS); do $(call test_run, $${t}) > $${t}_result; done
	@echo testing -O1
	@for t in $(TARGETS_O1); do $(call test_and_diff, $${t}, $${t%_O1}_result); done
	@echo testing -O2
	@for t in $(TARGETS_O2); do $(call test_and_diff, $${t}, $${t%_O2}_result); done
	@echo testing -O3
	@for t in $(TARGETS_O3); do $(call test_and_diff, $${t}, $${t%_O3}_result); done
	@echo testing -Os
	@for t in $(TARGETS_Os); do $(call test_and_diff, $${t}, $${t%_Os}_result); done

clean:
	$(RM) $(ALL_TARGETS) *.o uftrace.data* gmon.out *-diff

.PHONY: clean test arch
