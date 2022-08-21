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
#  [0] base: xxx   (from uftrace record -d yyy -F main tests/t-diff 1 )
#  [1] diff: yyy   (from uftrace record -d xxx -F main tests/t-diff 0 )
#
                     Total time (diff)                      Self time (diff)                       Calls (diff)   Function
   ===================================   ===================================   ================================   ====================
     1.012 us    1.017 us    -0.005 us     1.012 us    1.017 us    -0.005 us            1          1         +0   atoi
     2.796 ms    1.268 ms    +1.528 ms     3.031 us    1.644 us    +1.387 us            1          1         +0   main
     2.563 ms    1.265 ms    +1.297 ms     5.972 us    2.706 us    +3.266 us            2          1         -1   foo
   484.028 us  157.853 us  +326.175 us     4.056 us    0.979 us    +3.077 us            3          1         -2   bar
     2.782 ms    1.261 ms    +1.521 ms     2.782 ms    1.261 ms    +1.521 ms            6          2         -4   usleep
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
        self.option = '-f total,self,call --diff-policy full,no-abs -s call,func'
        self.exearg = '-d %s --diff %s' % (YDIR, XDIR)

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
