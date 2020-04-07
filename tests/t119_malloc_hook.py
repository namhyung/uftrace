#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'malloc-hook', ldflags='-ldl', result="""
# DURATION    TID     FUNCTION
            [ 4408] | main() {
   0.470 us [ 4408] |   malloc();
   0.390 us [ 4408] |   free();
   1.512 us [ 4408] | } /* main */
""")

    def setup(self):
        self.option = '-F main'
