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
#  [0] base: xxx   (from uftrace record -d yyy -F main tests/t-diff 1 )
#  [1] diff: yyy   (from uftrace record -d xxx -F main tests/t-diff 0 )
#
                    Total time (diff)                      Self time (diff)                       Calls (diff)   Function
  ===================================   ===================================   ================================   ================================================
    1.075 us    1.048 us    -0.027 us     1.075 us    1.048 us    -0.027 us            1          1         +0   atoi
  158.971 us    0.118 us  -158.853 us     1.437 us    0.118 us    -1.319 us            1          1         +0   bar
    1.235 ms    0.645 us    -1.235 ms     3.276 us    0.527 us    -2.749 us            1          1         +0   foo
    1.309 ms    3.975 us    -1.305 ms     2.601 us    2.282 us    -0.319 us            1          1         +0   main
    1.300 ms           -    -1.300 ms     1.300 ms           -    -1.300 ms            3          0         -3   usleep
""")

    def pre(self):
        record_cmd = '%s record -d %s -F main %s 0' % (TestBase.uftrace_cmd, XDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        record_cmd = '%s record -d %s -F main %s 1' % (TestBase.uftrace_cmd, YDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '--diff-policy full,no-abs -s call,total'
        return '%s report -d %s --diff %s %s' % (uftrace, YDIR, XDIR, options)

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
            # [0]  [1]  [2]  [3]  [4]  [5]   [6]  [7]  [8]  [9]  [10] [11]   [12]   [13]   [14]    [15]
            # tT/0 unit tT/1 unit tT/d unit  tS/0 unit tS/1 unit tS/d unit   call/0 call/1 call/d  function
            if line[-1].startswith('__'):
                continue
            result.append('%s %s %s %s' % (line[-4], line[-3], line[-2], line[-1]))

        return '\n'.join(result)
