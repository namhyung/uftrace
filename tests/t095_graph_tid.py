#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='a'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', result="""
#
# function graph for 'a' (session: de8436a173b22b1c)
#

backtrace
================================
 backtrace #0: hit 1, time   6.602 us
   [0] main (0x4005c5)
   [1] a (0x400782)

calling functions
================================
   6.602 us : (1) a
   6.094 us : (1) b
   5.680 us : (1) c
   4.234 us : (1) getpid
""", sort='graph')

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
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
        return '%s graph -d %s --tid %d %s' % (TestBase.ftrace, TDIR, t, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
