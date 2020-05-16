#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
  Total time   Total max    Self min       Calls   Function
  ==========  ==========  ==========  ==========   ====================
   10.297 ms   10.297 ms   10.297 ms           1   usleep
   11.173 ms   11.173 ms  499.317 us           1   main
   10.467 ms   10.467 ms  169.727 us           1   bar
  204.033 us   37.300 us   33.148 us           6   loop
  207.139 us  105.930 us    1.190 us           2   foo
    0.763 us    0.763 us    0.763 us           1   __monstartup
    0.299 us    0.299 us    0.299 us           1   __cxa_atexit
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '-f total,total-max,self-min,call -s self-min,total-min'

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
            # [0]         [1]   [2]        [3]   [4]       [5]  [6]     [7]
            # total_time  unit  total_max  unit  self_min  unit called  function
            if line[-1].startswith('__'):
                continue
            result.append('%s %s' % (line[-2], line[-1]))

        return '\n'.join(result)
