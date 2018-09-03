#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', result="""
# Function Call Graph for 'main' (session: 54047ea45c46ad91)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  10.329 ms
   [0] main (0x4004e0)

========== FUNCTION CALL GRAPH ==========
  10.329 ms : (1) main
  53.100 us :  +-(2) foo
  50.745 us :  | (6) loop
            :  | 
  10.150 ms :  +-(1) bar
  10.102 ms :    (1) usleep
  10.088 ms :    (1) linux:schedule
""", sort='graph')

    def pre(self):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        options = '-d %s -E %s' % (TDIR, 'linux:schedule')
        record_cmd = '%s record %s %s' % (TestBase.uftrace_cmd, options, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s %s' % (TestBase.uftrace_cmd.split()[0], TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
