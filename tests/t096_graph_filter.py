#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='a'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', result="""
# Function Call Graph for 'a' (session: 93175b4bdd9d0ddf)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   4.217 us
   [0] main (0x4005c0)
   [1] a (0x4007a1)

========== FUNCTION CALL GRAPH ==========
   4.217 us : (1) a
   3.876 us : (1) b
""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s -F main -N c %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
