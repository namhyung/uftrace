#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', result="""
#
# function graph for 'main'
#

backtrace
================================
 backtrace #0: hit 1, time  10.293 ms
   [0] main (0x4004f0)

calling functions
================================
  10.293 ms : (1) main
  46.626 us :  +-(2) foo
  44.360 us :  | (6) loop
            :  | 
  10.138 ms :  +-(1) bar
  10.100 ms :    (1) usleep
  10.098 ms :    (1) linux:schedule
""", sort='graph')

    def pre(self):
        options = '-d %s -E %s' % (TDIR, 'linux:schedule')
        record_cmd = '%s record %s %s' % (TestBase.ftrace, options, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
