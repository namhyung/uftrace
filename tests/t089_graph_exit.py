#!/usr/bin/env python

from runtest import TestBase

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

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.exearg = 'main'
