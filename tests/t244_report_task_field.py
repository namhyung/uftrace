#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread', """
     TID   Num funcs  Task name
  ======  ==========  ====================
   36562           1  t-thread
   36578           4  t-thread
   36577           4  t-thread
   36580           4  t-thread
   36579           4  t-thread
""", ldflags='-pthread')

    def prepare(self):
        self.subcmd = 'record'
        self.option = '--no-libcall'
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
