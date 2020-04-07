#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
# Function Call Graph for 'main' (session: 67af3e650b051216)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  10.148 ms
   [0] main (0x560e956bd610)

========== FUNCTION CALL GRAPH ==========
# TOTAL TIME  SELF TIME      ADDRESS     FUNCTION
   10.148 ms   37.889 us  560e956bd610 : (1) main
   15.991 us    0.765 us  560e956bd7ce :  +-(2) foo
   15.226 us   15.226 us  560e956bd7a0 :  | (6) loop
                                       :  | 
   10.094 ms   13.365 us  560e956bd802 :  +-(1) bar
   10.081 ms   10.081 ms  560e956bd608 :    (1) usleep
""", sort='graph')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '-f +self,addr'
        self.exearg = 'main'
