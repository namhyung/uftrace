#!/usr/bin/env python

from runtest import TestBase
import os.path

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', result="""
# Function Call Graph for 'a' (session: 5eec64959f2b2e87)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   4.290 us
   [0] main (0x4005c0)
   [1] a (0x4007a1)

========== FUNCTION CALL GRAPH ==========
   4.290 us : (1) a
   3.970 us : (1) b
   3.580 us : (1) c
   2.616 us : (1) getpid
""", sort='graph')

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

        self.subcmd = 'graph'
        self.option = '--tid %d' % t
        self.exearg = 'a'
