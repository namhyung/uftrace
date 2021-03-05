#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', result="""
# Function Call Graph for 'getpid' (session: adff9f265b25c0d8)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   2.010 us
   [0] main (0x400530)
   [1] a (0x4006f1)
   [2] b (0x4006c1)
   [3] c (0x400686)
   [4] getpid (0x4004d0)

========== FUNCTION CALL GRAPH ==========
   2.010 us : (1) getpid
""", sort='graph')

    def prepare(self):
        self.subcmd = 'record'
        self.exearg = 't-' + self.name
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.exearg = 'getpid'
