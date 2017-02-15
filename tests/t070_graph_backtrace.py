#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='getpid'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', result="""
#
# function graph for 'getpid'
#

backtrace
================================
 backtrace #0: hit 1, time   1.622 us
   [0] main (0x4004f0)
   [1] a (0x40069f)
   [2] b (0x400674)
   [3] c (0x400636)
   [4] getpid (0x400490)

calling functions
================================
   1.622 us : (1) getpid
""", sort='graph')

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-abc')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
