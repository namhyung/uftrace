def uftrace_entry(ctx):
        if "args" in ctx:
        	print(ctx["name"] + " has args")
	        
def uftrace_exit(ctx):
	if "retval" in ctx:
    		print(ctx["name"] + " has retval")

				

