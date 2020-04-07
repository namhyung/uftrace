#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
   1.138 us [28141] | __monstartup();
   2.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   a() {
   1.915 us [28141] |     b();
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    def setup(self):
        self.option = '--max-stack=3'
