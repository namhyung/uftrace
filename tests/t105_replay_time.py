#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [32537] | main() {
            [32537] |   foo() {
            [32537] |     bar() {
   2.080 ms [32537] |       usleep();
   2.084 ms [32537] |     } /* bar */
   2.102 ms [32537] |   } /* foo */
   2.103 ms [32537] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-t 1ms'
