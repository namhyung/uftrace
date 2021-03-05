#!/usr/bin/env python

from runtest import TestBase

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

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '-t 1ms'
        self.exearg = 'main'
