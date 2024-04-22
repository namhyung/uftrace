#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
       Total avg   Total min   Total max  Total stdv  Function
      ==========  ==========  ==========  ==========  ====================
       10.436 ms   10.436 ms   10.436 ms       0.00%   main
       10.383 ms   10.383 ms   10.383 ms       0.00%   bar
       10.368 ms   10.368 ms   10.368 ms       0.00%   usleep
        8.245 us    7.724 us    8.767 us       6.42%   foo
        2.532 us    2.484 us    2.725 us       3.61%   loop
    """)

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--avg-total'

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            line = ln.split()
            if line[1] == 'avg':
                continue
            if line[0].startswith('='):
                continue
            # A report line consists of following data
            # [0]        [1]   [2]        [3]   [4]        [5]   [6]
            # avg_total  unit  min_total  unit  max_total  unit  function
            if line[-1].startswith('__'):
                continue
            result.append(line[-1])

        return '\n'.join(result)
