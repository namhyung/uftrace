#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'malloc', """
# DURATION    TID     FUNCTION
            [16726] | main() {
   0.426 us [16726] |   malloc();
   0.397 us [16726] |   free();
   3.074 us [16726] | } /* main */
""")

    def setup(self):
        self.option = '-F main'
