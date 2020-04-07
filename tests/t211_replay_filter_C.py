#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION     TID     FUNCTION
            [ 30702] | main() {
            [ 30702] |   foo() {
   6.933 us [ 30702] |     mem_alloc();
   2.139 ms [ 30702] |   } /* foo */
   2.141 ms [ 30702] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-C mem_alloc'
