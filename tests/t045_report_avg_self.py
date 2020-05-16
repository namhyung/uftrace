#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
    Self avg    Self min    Self max  Function
  ==========  ==========  ==========  ====================
   10.288 ms   10.288 ms   10.288 ms  usleep
  598.518 us  598.518 us  598.518 us  main
  249.854 us  249.854 us  249.854 us  bar
   39.967 us   39.801 us   40.275 us  loop
    1.044 us    0.884 us    1.205 us  foo
    0.701 us    0.701 us    0.701 us  __monstartup   # ignore this
    0.270 us    0.270 us    0.270 us  __cxa_atexit   # and this too
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
            if line[6].startswith('__'):
                continue
            result.append(line[6])

        return '\n'.join(result)
