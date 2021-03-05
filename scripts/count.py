count = 0

def uftrace_begin(ctx):
    pass

def uftrace_entry(ctx):
    global count
    count += 1

def uftrace_exit(ctx):
    pass

def uftrace_end():
    print(count)
