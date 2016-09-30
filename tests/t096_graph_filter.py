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

""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s -F main -N c %s' % (TestBase.ftrace, TDIR, FUNC)

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
