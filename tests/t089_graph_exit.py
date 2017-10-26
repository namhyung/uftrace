#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exit', result="""
# Function Call Graph for 'main' (session: 095c3a95937bdbae)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   0.527 us
   [0] main (0x400480)

========== FUNCTION CALL GRAPH ==========
   0.527 us : (1) main
   0.387 us : (1) foo
            : (1) exit
""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
