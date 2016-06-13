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
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-sort')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s %s' % (TestBase.ftrace, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        mode = 0
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#') or ln.startswith('='):
                continue
            if ln.startswith('backtrace'):
                mode = 1
                continue
            if ln.startswith('calling'):
                mode = 2
                continue
            if mode == 1:
                if ln.startswith(' backtrace #'):
                    result.append(ln.split(',')[0])  # remove time part
                if ln.startswith('   ['):
                    result.append(ln.split('(')[0])  # remove '(addr)' part
            if mode == 2:
                result.append(ln.split(':')[1])      # remove time part

        return '\n'.join(result)
