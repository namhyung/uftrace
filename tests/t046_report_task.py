#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-name', """
  Total time   Self time   Num funcs     TID  Task name
  ==========  ==========  ==========  ======  ================
  772.936 us  136.238 us           9   2569   t-thread-name
  178.218 us  101.132 us           3   2571   t-thread-name
  174.537 us   83.934 us           3   2573   t-thread-name
  172.378 us   90.137 us           3   2574   t-thread-name
   63.568 us   63.568 us           3   2572   t-thread-name
""", ldflags='-pthread')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--task'

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
            # [0]         [1]   [2]        [3]   [4]        [5]  [6]
            # total_time  unit  self_time  unit  num_funcs  tid  task_name
            if line[4].startswith('__'):
                continue
            result.append(line[6])

        return '\n'.join(result)
