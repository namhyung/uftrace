#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
main;foo;bar;usleep 1
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'
        self.option = '--flame-graph --sample-time=2ms'

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '':
                continue
            result.append(ln)
        return '\n'.join(result)
