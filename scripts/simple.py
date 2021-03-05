def uftrace_begin(ctx):
    print("program begins...")

def uftrace_entry(ctx):
    func = ctx["name"]
    print("entry : " + func + "()")

def uftrace_exit(ctx):
    func = ctx["name"]
    print("exit  : " + func + "()")

def uftrace_end():
    print("program is finished")
