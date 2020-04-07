#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
    2.103 ms    0.910 us           1  main
    2.102 ms   18.787 us           1  foo
    2.084 ms    4.107 us           1  bar
    2.080 ms    2.080 ms           1  usleep
""", sort='report')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '-t 1ms'
