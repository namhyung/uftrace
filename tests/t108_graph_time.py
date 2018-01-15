#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# Function Call Graph for 'main' (session: b78e9c27042adaa7)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   2.109 ms
   [0] main (0x400570)

========== FUNCTION CALL GRAPH ==========
   2.109 ms : (1) main
   2.109 ms : (1) foo
   2.098 ms : (1) bar
   2.096 ms : (1) usleep
""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -t 1ms -d %s %s' % (TestBase.uftrace_cmd, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
