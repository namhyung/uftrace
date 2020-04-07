#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
            [28141] | a() {
   1.915 us [28141] |   b();
   2.405 us [28141] | } /* a */
""", sort='simple')

    def setup(self):
        self.option = '-F a -N c'
