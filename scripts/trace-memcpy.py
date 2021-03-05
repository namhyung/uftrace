#
# trace-memcpy.py
#
# uftrace-option: --nest-libcall -T memcpy@filter,arg3
#
#   void *memcpy(void *dest, const void *src, size_t n);
#

# Only "memcpy" calls this script and other functions never.
UFTRACE_FUNCS = [ "memcpy" ]

count = 0
total_bytes = 0

def uftrace_begin(ctx):
    pass

def uftrace_entry(ctx):
    global count
    global total_bytes
    count += 1
    total_bytes += ctx["args"][0]

def uftrace_exit(ctx):
    pass

def uftrace_end():
    global count
    global total_bytes
    print("%d times memcpy called" % count)
    print("%d bytes copied" % total_bytes)
