#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [16873] | main() {
            [16873] |   foo() {
            [16873] |     mem_alloc() {
   1.675 us [16873] |       malloc();
   6.867 us [16873] |     } /* mem_alloc */
            [16873] |     bar() {
   2.068 ms [16873] |       usleep();
   2.071 ms [16873] |     } /* bar */
   2.085 ms [16873] |   } /* foo */
   2.086 ms [16873] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-t 1ms -T mem_alloc@time=0'
