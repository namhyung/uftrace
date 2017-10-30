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
  Total time    Self time        Calls   Function
  ==========   ==========   ==========   ====================
      -5.40%       -5.40%           +0   atoi
    +999.99%     +875.84%           +0   bar
    +999.99%     +498.85%           +0   foo
    +999.99%      +10.47%           +0   main
    +999.99%     +999.99%           +3   usleep
""")

    def pre(self):
        record_cmd = '%s record -d %s -F main %s 0' % (TestBase.ftrace, XDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        record_cmd = '%s record -d %s -F main %s 1' % (TestBase.ftrace, YDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.ftrace
        options = '--diff-policy percent -s func'
        return '%s report -d %s --diff %s %s' % (uftrace, XDIR, YDIR, options)

    def post(self, ret):
        sp.call(['rm', '-rf', XDIR, YDIR])
        return ret

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
