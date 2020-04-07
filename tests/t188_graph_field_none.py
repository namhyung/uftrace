#!/usr/bin/env python

from runtest import TestBase

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

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '-f none'
        self.exearg = 'main'
