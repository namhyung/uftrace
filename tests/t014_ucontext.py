#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'ucontext', """
# DURATION    TID     FUNCTION
  79.593 us [28383] | __cxa_atexit();
            [28383] | main() {
   1.606 us [28383] |   getcontext();
   1.584 us [28383] |   makecontext();
            [28383] |   foo() {
            [28383] |     swapcontext() {
            [28383] |       bar() {
   2.384 us [28383] |         getpid();
   5.700 us [28383] |       } /* bar */
   8.716 us [28383] |     } /* swapcontext */
   9.489 us [28383] |   } /* foo */
   0.130 us [28383] |   baz();
  15.586 us [28383] | } /* main */
""")
