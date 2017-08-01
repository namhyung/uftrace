count = 0

def uftrace_begin():
    pass

def uftrace_entry(args):
    global count
    count += 1

def uftrace_exit(args):
    pass

def uftrace_end():
    print(count)
