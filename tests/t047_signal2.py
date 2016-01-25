#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal2', """
# DURATION    TID     FUNCTION
   3.966 us [24050] | __monstartup();
   0.342 us [24050] | __cxa_atexit();
            [24050] | main() {
   0.483 us [24050] |   signal();
   1.476 us [24050] |   setitimer();
            [24050] |   foo() {
            [24050] |     bar() {
   0.401 us [24050] |       sighandler();
   4.074 ms [24050] |     } /* bar */
            [24050] |     bar() {
   0.086 us [24050] |       sighandler();
   3.330 ms [24050] |     } /* bar */
            [24050] |     bar() {
   0.099 us [24050] |       sighandler();
   3.331 ms [24050] |     } /* bar */
  10.736 ms [24050] |   } /* foo */
  10.738 ms [24050] | } /* main */
""")
