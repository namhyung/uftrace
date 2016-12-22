#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
#
# function graph for 'main' (session: 0bc5da823389c319)
#

backtrace
================================
 backtrace #0: hit 1, time   2.103 ms
   [0] main (0x400550)

calling functions
================================
   2.103 ms : (1) main
   2.102 ms : (1) foo
   2.084 ms : (1) bar
   2.080 ms : (1) usleep

""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -t 1ms -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
