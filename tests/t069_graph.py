#!/usr/bin/env python3

from runtest import TestBase

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

    def prepare(self):
        self.subcmd = 'record'
        self.exearg = 't-' + self.name
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.exearg = 'main'
