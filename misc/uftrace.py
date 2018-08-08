import sys
import trace_python

sys.settrace(trace_python.trace)

execfile(sys.argv[1])
