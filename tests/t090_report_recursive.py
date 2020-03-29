#!/usr/bin/env python

from runtest import TestBase

# This test checks total time of recursive calls not exceeds self time.
# But the actual time will be different than this example run.
# So just use 'same' symbol to indicate it handles recursive calls properly.
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fibonacci', """
  Total time   Self time       Calls  Function
  ==========  ==========  ==========  ====================================
   25.024 us    2.718 us           1  main
   19.600 us   19.600 us           9  fib
    2.853 us    2.853 us           1  __monstartup
    2.706 us    2.706 us           1  atoi
    2.194 us    2.194 us           1  __cxa_atexit
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'

    def sort(self, output):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            line = ln.split()
            if line[0].startswith('='):
                continue
            if line[5] != 'fib':
                continue
            # A report line consists of following data
            # [0]         [1]   [2]        [3]   [4]    [5]
            # total_time  unit  self_time  unit  calls  function
            if line[0] == line[2]:
                result.append('same same')
            else:
                result.append('%s %s' % (line[0], line[2]))

        return '\n'.join(result)
