#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
   Avg total   Min total   Max total  Function
  ==========  ==========  ==========  ====================================
    1.152 ms    1.152 ms    1.152 ms  main
    1.080 ms    1.080 ms    1.080 ms  bar
    1.078 ms    1.078 ms    1.078 ms  usleep
   70.176 us   70.176 us   70.176 us  __monstartup   # ignore this
    3.665 us    2.976 us    4.354 us  foo
    1.051 us    0.868 us    1.912 us  loop
    1.002 us    1.002 us    1.002 us  __cxa_atexit   # and this too
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-sort')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report --avg-total -d %s' % (TestBase.ftrace, TDIR)

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
            if line[0] == 'Avg':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]        [1]   [2]        [3]   [4]        [5]   [6]
            # avg_total  unit  min_total  unit  max_total  unit  function
            if line[6].startswith('__'):
                continue
            result.append(line[6])

        return '\n'.join(result)
