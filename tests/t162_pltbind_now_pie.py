#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', """
# DURATION    TID     FUNCTION
            [15973] | main() {
   5.903 us [15973] |   fopen();
   4.374 us [15973] |   fclose();
  15.262 us [15973] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        return TestBase.build(self, name, cflags + " -fpie",
                              ldflags + " -Wl,-pie,-z,now,-z,relro")
