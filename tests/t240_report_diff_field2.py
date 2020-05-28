#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

XDIR='xxx'
YDIR='yyy'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'diff', """
#
# uftrace diff
#  [0] base: xxx   (from uftrace record -d xxx -F main tests/t-diff 0 )
#  [1] diff: yyy   (from uftrace record -d yyy -F main tests/t-diff 1 )
#
    Total time        Calls   Function
  ============   ==========   ====================
     +1.296 ms           +0   main
     +1.292 ms           +3   usleep
     +1.225 ms           +0   foo
   +158.450 us           +0   bar
     -0.066 us           +0   atoi
""")

    def prerun(self, timeout):
        self.subcmd = 'record'
        self.option = '-d %s -F main' % XDIR
        self.exearg = 't-' + self.name + ' 0'
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())

        self.option = '-d %s -F main' % YDIR
        self.exearg = 't-' + self.name + ' 1'
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'report'
        self.option = '-f total,call --diff-policy compact,no-percent,abs'  # new default
        self.exearg = '-d %s --diff %s' % (XDIR, YDIR)

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.startswith('#') or ln.strip() == '':
                continue
            line = ln.split()
            if line[0] == 'Total':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]  [1]    [2]   [3]
            # total unit  call  function
            if line[-1].startswith('__'):
                continue
            result.append('%s %s' % (line[-2], line[-1]))

        return '\n'.join(result)
