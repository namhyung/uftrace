import os
import sys

sys.argv = sys.argv[1:len(sys.argv)]

filename = sys.argv[0]
if os.path.exists(filename) or filename.count('/') > 0:
    os.environ["UFTRACE_PYMAIN"] = filename
    pass
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

import uftrace_python
code = open(sys.argv[0]).read()
sys.setprofile(uftrace_python.trace)
exec(code)
sys.setprofile(None)
