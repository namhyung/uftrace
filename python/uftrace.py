import os
import sys
import uftrace_python

sys.argv = sys.argv[1:len(sys.argv)]

filename = sys.argv[0]
if os.path.exists(filename) or filename[0] == '/':
    os.environ["UFTRACE_PYMAIN"] = filename
    if filename[0] == '/':
        pathname = filename
    else:
        pathname = os.getcwd() + '/' + filename
else:
    for dir in os.environ["PATH"].split(":"):
        pathname = dir + '/' + filename
        try:
            f = open(pathname)
            sys.argv[0] = pathname
            os.environ["UFTRACE_PYMAIN"] = pathname
            f.close()
            break
        except OSError:
            continue

new_globals = globals()
new_globals["__file__"] = pathname

code = open(sys.argv[0]).read()
sys.setprofile(uftrace_python.trace)
exec(code, new_globals)
sys.setprofile(None)
