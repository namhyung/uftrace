#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

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
    Total time     Self time         Calls   Function
   ===========   ===========   ===========   ====================
        +2.99%        +2.99%            +0   atoi
      +195.87%      +104.40%            +2   bar
       +95.74%       +16.14%            +1   foo
      +113.47%       +88.88%            +0   main
      +113.96%      +113.96%            +4   usleep
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
        self.pr_debug('prerun command: %s' + record_cmd)
        sp.call(record_cmd.split())

        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'report'
        self.option = '--diff-policy percent -s func'
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
            # [0]   [1]      [2]  [3]      [4]   [5]
            # total percent  self percent  call  function
            if line[-1].startswith('__'):
                continue
            result.append('%s %s' % (line[-2], line[-1]))

        return '\n'.join(result)
