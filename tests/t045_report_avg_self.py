#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
        Self avg    Self min    Self max   Self stdv  Function
      ==========  ==========  ==========  ==========  ====================
       10.128 ms   10.128 ms   10.128 ms       0.00%   usleep
       37.113 us   37.113 us   37.113 us       0.00%   main
       13.597 us   13.597 us   13.597 us       0.00%   bar
        2.495 us    2.479 us    2.535 us       2.70%   loop
        1.066 us    1.066 us    1.066 us       0.00%   __monstartup
        0.569 us    0.569 us    0.569 us       0.00%   __cxa_atexit
        0.372 us    0.292 us    0.452 us      21.51%   foo
    """)

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--avg-self'

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
            # [0]       [1]   [2]       [3]   [4]       [5]   [6]
            # avg_self  unit  min_self  unit  max_self  unit  function
            if line[-1].startswith('__'):
                continue
            result.append(line[-1])

        return '\n'.join(result)
