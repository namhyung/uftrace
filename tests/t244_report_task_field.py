#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-name', """
     TID   Num funcs  Task name
  ======  ==========  ====================
   22038           9  t-thread-name
   22040           3  t-thread-name
   22042           3  t-thread-name
   22041           3  t-thread-name
   22043           3  t-thread-name
""", ldflags='-pthread')

    def build(self, name, cflags='', ldflags=''):
        if cflags.find('-pg') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--task -f tid,func'

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
            # [0]  [1]        [2]
            # tid  num_funcs  task_name
            result.append('%s %s' % (line[-2], line[-1]))

        return '\n'.join(result)
