#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================
   18.227 us    1.991 us           1  main
    0.734 us    0.590 us           1  sighandler
    0.353 us    0.353 us           2  foo
    0.144 us    0.144 us           1  bar
""", sort='report')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--no-libcall'
