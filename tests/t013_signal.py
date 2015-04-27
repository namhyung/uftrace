#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# DURATION    TID     FUNCTION
  78.933 us [28901] | __cxa_atexit();
            [28901] | main() {
   1.930 us [28901] |   signal();
            [28901] |   raise() {
   0.236 us [28901] |     sighandler();
  13.464 us [28901] |   } /* raise */
  17.113 us [28901] | } /* main */
""")
