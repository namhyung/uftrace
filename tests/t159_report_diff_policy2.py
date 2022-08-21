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
     0.965 us    0.942 us    +0.023 us     0.965 us    0.942 us    +0.023 us            1          1         +0   atoi
     2.735 ms    1.219 ms    +1.516 ms     3.370 us    1.528 us    +1.842 us            1          1         +0   main
     2.501 ms    1.216 ms    +1.284 ms     4.159 us    0.950 us    +3.209 us            2          1         -1   foo
   481.377 us  156.153 us  +325.224 us     3.160 us    0.557 us    +2.603 us            3          1         -2   bar
     2.724 ms    1.215 ms    +1.509 ms     2.724 ms    1.215 ms    +1.509 ms            6          2         -4   usleep
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
        self.option = '--diff-policy full,no-abs -s call,func'
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
