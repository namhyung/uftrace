#!/usr/bin/env python3

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
     Total avg     Total min     Total max    Total stdv   Function
   ===========   ===========   ===========   ===========   ====================
     -0.040 us     -0.040 us     -0.040 us      +0.00%pt   atoi
     +0.824 us     +1.519 us     -0.423 us      +0.35%pt   bar
     +5.102 us    +18.455 us     -8.251 us      +0.77%pt   foo
     -1.434 ms     -1.434 ms     -1.434 ms      +0.00%pt   main
   +165.366 us    +86.906 us    -13.878 us     -12.15%pt   usleep
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
        self.option = '--avg-total -s func'
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
            # [0] [1]   [2] [3]   [4] [5]   [6]  [7]   [8]
            # tot unit  min unit  max unit  stdv unit  function
            if line[-1].startswith('__'):
                continue
            result.append(line[-1])

        return '\n'.join(result)
