ASFLAGS = -fPIC
LDFLAGS = -r

sdir = $(srcdir)/arch/x86_64
odir = $(objdir)/arch/x86_64

include $(srcdir)/config/Makefile.include

ARCH_ENTRY_SRC = $(wildcard $(sdir)/*.S)

all: $(odir)/entry.op

$(odir)/entry.op: $(patsubst $(sdir)/%.S,$(odir)/%.op,$(ARCH_ENTRY_SRC))
	$(QUIET_LINK)$(LD) $(LDFLAGS) -o $@ $^

$(odir)/%.op: $(sdir)/%.S
	$(QUIET_ASM)$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	$(RM) $(odir)/*.op $(odir)/*.o
