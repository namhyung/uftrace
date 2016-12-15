#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
    2.103 ms    0.910 us           1  main
    2.102 ms   18.787 us           1  foo
    2.084 ms    4.107 us           1  bar
    2.080 ms    2.080 ms           1  usleep
""")

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report -t 1ms -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            line = ln.split()
            if line[0] == 'Total':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]         [1]   [2]        [3]   [4]     [5]
            # total_time  unit  self_time  unit  called  function
            if line[5].startswith('__'):
                continue
            result.append('%s %s' % (line[4], line[5]))

        return '\n'.join(result)
