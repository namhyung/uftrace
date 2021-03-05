#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', result="""
# Function Call Graph for 'a' (session: 93175b4bdd9d0ddf)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   4.217 us
   [0] main (0x4005c0)
   [1] a (0x4007a1)

========== FUNCTION CALL GRAPH ==========
   4.217 us : (1) a
   3.876 us : (1) b
""", sort='graph')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '-F main -N c'
        self.exearg = 'a'
