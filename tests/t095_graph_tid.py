#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='a'

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

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        import os.path
        t = 0
        for ln in open(os.path.join(TDIR, 'task.txt')):
            if not ln.startswith('TASK'):
                continue
            try:
                t = int(ln.split()[2].split('=')[1])
            except:
                pass
        if t == 0:
            return 'FAILED TO FIND TID'
        return '%s graph -d %s --tid %d %s' % (TestBase.uftrace_cmd, TDIR, t, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
