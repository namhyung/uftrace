#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# DURATION    TID     FUNCTION
  78.933 us [28901] | __cxa_atexit();
            [28901] | main() {
   0.996 us [28901] |   foo();
   1.930 us [28901] |   signal();
            [28901] |   raise() {
            [28901] |     sighandler() {
   0.236 us [28901] |       bar();
   0.236 us [28901] |     } /* sighandler */
  13.464 us [28901] |   } /* raise */
   0.102 us [28901] |   foo();
  17.113 us [28901] | } /* main */
""")
