#!/usr/bin/env python

from runtest import TestBase
import os.path

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
  849.948 us   20.543 us           1  main
  691.873 us  691.873 us           1  wait
  130.930 us  130.930 us           1  fork
    6.602 us    0.508 us           1  a
    6.094 us    0.414 us           1  b
    5.680 us    1.446 us           1  c
    4.234 us    4.234 us           1  getpid
    1.568 us    1.568 us           1  __monstartup
    1.140 us    1.140 us           1  __cxa_atexit
""", sort='report')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        t = 0
        for ln in open(os.path.join('uftrace.data', 'task.txt')):
            if not ln.startswith('TASK'):
                continue
            try:
                t = int(ln.split()[2].split('=')[1])
            except:
                pass
        if t == 0:
            self.subcmd = 'FAILED TO FIND TID'
            return

        self.subcmd = 'report'
        self.option = '--tid %d' % t
