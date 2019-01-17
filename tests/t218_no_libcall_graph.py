#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# Function Call Graph for 't-signal' (session: 0fa6f0e678964bde)
========== FUNCTION CALL GRAPH ==========
# TOTAL TIME   FUNCTION
   18.227 us : (1) t-signal
   18.227 us : (1) main
    0.353 us :  +-(2) foo
             :  | 
    0.734 us :  +-(1) sighandler
    0.144 us :    (1) bar
""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph --no-libcall -d %s' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
