#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [18219] | main() {
            [18219] |   foo() {
            [18219] |     bar() {
   2.093 ms [18219] |       usleep();
   2.095 ms [18219] |     } /* bar */
   2.106 ms [18219] |   } /* foo */
   2.107 ms [18219] | } /* main */
""")

    def setup(self):
        self.option = '-t 1ms'
