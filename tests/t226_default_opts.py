#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep2', result="""
# DURATION     TID     FUNCTION
            [ 41487] | main() {
            [ 41487] |   foo() {
   5.107 ms [ 41487] |     usleep();
   8.220 ms [ 41487] |   } /* foo */
   9.336 ms [ 41487] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        self.option = '-t 2ms'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-t 4ms'
