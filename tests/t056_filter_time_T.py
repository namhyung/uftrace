#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [18260] | main() {
   2.088 ms [18260] |   foo();
   2.090 ms [18260] | } /* main */
""")

    def setup(self):
        self.option = '-t 1ms -T "mem_alloc@trace-off" -T "mem_free@trace-on"'
