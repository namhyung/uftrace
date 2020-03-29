#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [18224] | main() {
   2.083 ms [18224] |   foo();
   2.085 ms [18224] | } /* main */
""")

    def setup(self):
        self.option = '-t 1ms -N bar'
