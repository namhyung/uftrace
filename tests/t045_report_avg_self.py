#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
    Avg self    Min self    Max self  Function
  ==========  ==========  ==========  ====================================
    1.078 ms    1.078 ms    1.078 ms  usleep
   71.683 us   71.683 us   71.683 us  main
   70.176 us   70.176 us   70.176 us  __monstartup   # ignore this
    1.813 us    1.813 us    1.813 us  bar
    1.051 us    0.868 us    1.912 us  loop
    1.002 us    1.002 us    1.002 us  __cxa_atexit   # and this too
    0.509 us    0.359 us    0.660 us  foo
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-sort')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report --avg-self -d %s' % (TestBase.uftrace_cmd, TDIR)

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
            # [0]       [1]   [2]       [3]   [4]       [5]   [6]
            # avg_self  unit  min_self  unit  max_self  unit  function
            if line[6].startswith('__'):
                continue
            result.append(line[6])

        return '\n'.join(result)
