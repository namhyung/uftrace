LIB_ASFLAGS := -fPIC
LIB_CFLAGS := -O2 -g -D_GNU_SOURCE -fPIC -fvisibility=hidden -iquote $(srcdir)
CFLAGS := -O2 -g -D_GNU_SOURCE -iquote $(srcdir)
LINKFLAGS := -r

sdir := $(srcdir)/arch/x86_64
odir := $(objdir)/arch/x86_64

include $(srcdir)/Makefile.include

ARCH_ENTRY_SRC = $(wildcard $(sdir)/*.S)
ARCH_MCOUNT_SRC = $(wildcard $(sdir)/mcount-*.c) $(sdir)/regs.c
ARCH_UFTRACE_SRC = $(sdir)/cpuinfo.c $(sdir)/regs.c

all: $(odir)/entry.op

$(odir)/mcount-entry.op: $(patsubst $(sdir)/%.S,$(odir)/%.op,$(ARCH_ENTRY_SRC)) $(patsubst $(sdir)/%.c,$(odir)/%.op,$(ARCH_MCOUNT_SRC))
	$(QUIET_LINK)$(LD) $(LINKFLAGS) -o $@ $^

$(odir)/uftrace.o: $(patsubst $(sdir)/%.c,$(odir)/%.o,$(ARCH_UFTRACE_SRC))
	$(QUIET_LINK)$(LD) $(LINKFLAGS) -o $@ $^

$(odir)/%.op: $(sdir)/%.S
	$(QUIET_ASM)$(CC) $(LIB_ASFLAGS) -c -o $@ $<

$(odir)/%.op: $(sdir)/%.c
	$(QUIET_CC_FPIC)$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(odir)/%.o: $(sdir)/%.c
	$(QUIET_CC)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(odir)/*.op $(odir)/*.o
