#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
  Total time   Self time       Calls  Function [Source]
  ==========  ==========  ==========  ====================
    2.559 us    0.306 us           1  main [tests/s-abc.c:26]
    2.253 us    0.292 us           1  a [tests/s-abc.c:11]
    1.961 us    0.342 us           1  b [tests/s-abc.c:16]
    1.619 us    0.555 us           1  c [tests/s-abc.c:21]
    1.064 us    1.064 us           1  getpid
    0.372 us    0.372 us           1  __monstartup
    0.186 us    0.186 us           1  __cxa_atexit
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        self.option = '--srcline'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--srcline'

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
            # [0]         [1]   [2]        [3]   [4]     [5]       [6]
            # total_time  unit  self_time  unit  called  function  srcline
            if line[-1].startswith('__'):
                continue

            if len(line) < 7 :
                result.append('%s %s' % (line[-2], line[-1]))
            else :
                result.append('%s %s %s' % (line[-3], line[-2], line[-1][1:-1].split('/')[-1]))

        return '\n'.join(result)
