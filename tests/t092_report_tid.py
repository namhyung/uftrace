#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
  849.948 us   20.543 us           1  main
  691.873 us  691.873 us           1  wait
  130.930 us  130.930 us           1  fork
    6.602 us    0.508 us           1  a
    6.094 us    0.414 us           1  b
    5.680 us    1.446 us           1  c
    4.234 us    4.234 us           1  getpid
    1.568 us    1.568 us           1  __monstartup
    1.140 us    1.140 us           1  __cxa_atexit
""")

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        import os.path
        t = 0
        for ln in open(os.path.join(TDIR, 'task.txt')):
            if not ln.startswith('TASK'):
                continue
            try:
                t = int(ln.split()[2].split('=')[1])
            except:
                pass
        if t == 0:
            return 'FAILED TO FIND TID'
        return '%s report -d %s --tid %d' % (TestBase.ftrace, TDIR, t)

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
            # [0]         [1]   [2]        [3]   [4]    [5]
            # total_time  unit  self_time  unit  calls  function
            if line[5].startswith('__'):
                continue
            result.append('%s %s' % (line[4], line[5]))

        return '\n'.join(result)
