#!/usr/bin/env python

import os.path

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
        # Elements
        digraph "t-abc" {
            "t-abc" -> "main" [xlabel = "1"]
            "main" -> "a" [xlabel = "1"]
            "a" -> "b" [xlabel = "1"]
            "b" -> "c" [xlabel = "1"]
        }
        """)

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-F main -D 4 --graphviz'

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for line, ln in enumerate(output.split('\n')):
            # remove all comments
            ln = ln.strip()
            if ln.startswith('#'):
                continue
            result.append(ln)
        return '\n'.join(result)
