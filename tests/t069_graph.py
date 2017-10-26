#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', result="""
# Function Call Graph for 'main' (session: baa921f86e22e0c9)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  11.460 ms
   [0] main (0x40069e)

========== FUNCTION CALL GRAPH ==========
  11.460 ms : (1) main
 311.345 us :  +-(2) foo
 308.918 us :  | (6) loop
            :  | 
  10.362 ms :  +-(1) bar
  10.091 ms :    (1) usleep
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
