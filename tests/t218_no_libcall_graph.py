#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# Function Call Graph for 't-signal' (session: 0fa6f0e678964bde)
========== FUNCTION CALL GRAPH ==========
# TOTAL TIME   FUNCTION
   18.227 us : (1) t-signal
   18.227 us : (1) main
    0.353 us :  +-(2) foo
             :  | 
    0.734 us :  +-(1) sighandler
    0.144 us :    (1) bar
""", sort='graph')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '--no-libcall'
        self.exearg = ''
