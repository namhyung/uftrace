#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================
  187.817 us  187.817 us           6  loop
  189.598 us    1.781 us           2  foo
    0.657 us    0.657 us           1  __cxa_atexit
    1.323 us    1.323 us           1  __monstartup
   10.265 ms  157.616 us           1  bar
   10.921 ms  466.298 us           1  main
   10.107 ms   10.107 ms           1  usleep
""", sort='report')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '-s call,func'
