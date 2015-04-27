#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'longjmp', """
# DURATION    TID     FUNCTION
  63.615 us [29065] | __cxa_atexit();
            [29065] | main() {
   0.690 us [29065] |   _setjmp();
            [29065] |   foo() {
   0.907 us [29065] |     longjmp();
   0.105 us [29065] |     bar();
   0.XXX us [29065] |   } /* foo */
""")
