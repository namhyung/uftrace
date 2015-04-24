#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg', """
# DURATION    TID     FUNCTION
            [16325] | main() {
            [16325] |   foo() {
            [16325] |     bar() {
   0.567 us [16325] |       strcmp();
   1.779 us [16325] |     } /* bar */
            [16325] |     bar() {
   0.133 us [16325] |       strcmp();
   0.489 us [16325] |     } /* bar */
            [16325] |     bar() {
   0.081 us [16325] |       strcmp();
   0.381 us [16325] |     } /* bar */
   3.515 us [16325] |   } /* foo */
   0.235 us [16325] |   many();
            [16325] |   pass() {
   0.130 us [16325] |     check();
   0.427 us [16325] |   } /* pass */
  42.161 us [16325] | } /* main */
""")
