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
                 Total time (diff)                   Self time (diff)                       Calls (diff)   Function
  ================================   ================================   ================================   ================================================
    1.223 us    1.157 us    -5.40%     1.223 us    1.157 us    -5.40%            1          1         +0   atoi
    0.149 us  158.599 us  +999.99%     0.149 us    1.454 us  +875.84%            1          1         +0   bar
    0.672 us    1.226 ms  +999.99%     0.523 us    3.132 us  +498.85%            1          1         +0   foo
    4.874 us    1.301 ms  +999.99%     2.979 us    3.291 us   +10.47%            1          1         +0   main
           -    1.292 ms  +999.99%            -    1.292 ms  +999.99%            0          3         +3   usleep
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
            # [0]  [1]  [2]  [3]  [4]      [5]  [6]  [7]  [8]  [9]       [10]   [11]   [12]    [13]
            # tT/0 unit tT/1 unit percent  tS/0 unit tS/1 unit percent   call/0 call/1 call/d  function
            if line[-1].startswith('__'):
                continue
            result.append('%s %s %s %s' % (line[-4], line[-3], line[-2], line[-1]))

        return '\n'.join(result)
