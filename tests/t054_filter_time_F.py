#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', result="""
# DURATION    TID     FUNCTION
            [18229] | bar() {
   2.078 ms [18229] |   usleep();
   2.080 ms [18229] | } /* bar */
""", sort='simple')

    def setup(self):
        self.option = '-t 1ms -F bar'
