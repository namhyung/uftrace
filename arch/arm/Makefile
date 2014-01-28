CC = gcc
LD = ld
RM = rm -f

ASFLAGS = -fPIC
LDFLAGS = -r

ARCH_ENTRY_SRC = mcount.S

all: entry.op

entry.op: $(ARCH_ENTRY_SRC:.S=.op)
	$(LD) $(LDFLAGS) -o $@ $^

%.op: %.S
	$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	$(RM) *.op *.o
