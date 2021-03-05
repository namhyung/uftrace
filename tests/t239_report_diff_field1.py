#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

XDIR='xxx'
YDIR='yyy'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
#
# uftrace diff
#  [0] base: xxx   (from uftrace record -d xxx tests/t-abc )
#  [1] diff: yyy   (from uftrace record -d yyy tests/t-abc )
#
                 Total time (diff)                   Self time (diff)                  Nr. called (diff)   Function
  ================================   ================================   ================================   ====================================
    6.974 us    6.268 us   -10.12%     0.560 us    0.511 us    -8.75%            1          1         +0   main
    6.414 us    5.757 us   -10.24%     0.489 us    0.372 us   -23.93%            1          1         +0   a
    5.925 us    5.385 us    -9.11%     0.786 us    0.554 us   -29.52%            1          1         +0   b
    5.139 us    4.831 us    -5.99%     3.517 us    3.137 us   -10.80%            1          1         +0   c
    1.622 us    1.694 us    +4.44%     1.622 us    1.694 us    +4.44%            1          1         +0   getpid
""")

    def prerun(self, timeout):
        self.subcmd = 'record'
        self.option = '-d ' + XDIR
        self.exearg = 't-' + self.name
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())

        self.option = '-d ' + YDIR
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'report'
        self.option = '-f total,self,call --sort-column 0 --diff-policy full,percent'  # old behavior
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
            # [0]  [1]  [2]  [3]  [4]      [5]  [6]  [7]  [8]  [9]      [10]   [11]   [12]       [13]
            # tT/0 unit tT/1 unit percent  tS/0 unit tS/1 unit percent  call/0 call/1 call/diff  function
            if line[-1].startswith('__'):
                continue
            result.append('%s %s %s %s' % (line[-4], line[-3], line[-2], line[-1]))

        return '\n'.join(result)
