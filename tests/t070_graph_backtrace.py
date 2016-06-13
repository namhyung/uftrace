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
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-abc')
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
