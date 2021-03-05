#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', serial=True, result="""
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

    def prerun(self, timeout):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = '-E linux:schedule'
        self.exearg = 't-' + self.name

        record_cmd = TestBase.runcmd(self)
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'graph'
        self.option = ''
        self.exearg = 'main'

    def runcmd(self):
        cmd = TestBase.runcmd(self)
        return cmd.replace('--no-event', '')
