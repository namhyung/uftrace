#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
  Total time   Self time  Nr. called  Function
  ==========  ==========  ==========  ====================================
   36.388 us   36.388 us           6  loop
   37.525 us    1.137 us           2  foo
    1.078 ms    1.078 ms           1  usleep
    1.152 ms   71.683 us           1  main
   70.176 us   70.176 us           1  __monstartup   # ignore this
    1.080 ms    1.813 us           1  bar
    1.200 us    1.200 us           1  __cxa_atexit   # and this too
""", sort='report')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '-s call,self'
