#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================
    0.125 us    0.125 us           2  foo
    9.500 us    0.459 us           1  main
    0.209 us    0.126 us           1  sighandler
    0.083 us    0.083 us           1  bar
""", sort='report')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--no-libcall -s call,total'
