ASFLAGS = -fPIC
LDFLAGS = -r

include ../../config/Makefile.include

ARCH_ENTRY_SRC = mcount.S plthook.S

all: entry.op

entry.op: $(ARCH_ENTRY_SRC:.S=.op)
	$(QUIET_LINK)$(LD) $(LDFLAGS) -o $@ $^

%.op: %.S
	$(QUIET_ASM)$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	$(RM) *.op *.o
