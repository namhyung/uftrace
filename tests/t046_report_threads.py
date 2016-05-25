#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-name', """
    TID    Run time   Num funcs  Function
  =====  ==========  ==========  ====================================
   2569  772.936 us           9  main
   2571  178.218 us           3  thread_first
   2572   63.568 us           3  thread_second
   2573  174.537 us           3  thread_third
   2574  172.378 us           3  thread_fourth
""", ldflags='-pthread')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-thread-name')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s report --threads -d %s' % (TestBase.ftrace, TDIR)

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
            if line[0] == 'TID':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]  [1]       [2]   [3]        [4]
            # tid  run_time  unit  num_funcs  function
            if line[4].startswith('__'):
                continue
            result.append(line[4])

        return '\n'.join(result)
