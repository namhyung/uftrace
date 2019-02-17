import sys

if sys.version_info[0] < 3:
    import trace_python2
    sys.settrace(trace_python2.trace)
else:
    import trace_python3
    sys.settrace(trace_python3.trace)

sys.argv = sys.argv[1:]

progname = sys.argv[0]

globs = {
    '__file__': progname,
    '__name__': '__main__',
    '__package__': None,
    '__cached__': None,
}

exec(open(progname).read(), globs, globs)
