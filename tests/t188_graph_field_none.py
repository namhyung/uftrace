#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
# Function Call Graph for 'main' (session: 6085c5f021e501d0)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  10.321 ms
   [0] main (0x4004a0)

========== FUNCTION CALL GRAPH ==========
(1) main
 +-(2) foo
 | (6) loop
 | 
 +-(1) bar
   (1) usleep

""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -f none -d %s %s' % (TestBase.uftrace_cmd, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
