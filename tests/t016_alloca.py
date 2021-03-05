#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'alloca', """
# DURATION    TID     FUNCTION'
  75.736 us [ 6681] | __cxa_atexit();
            [ 6681] | main() {
            [ 6681] |   foo() {
   2.153 us [ 6681] |     strncpy();
   3.073 us [ 6681] |   } /* foo */
            [ 6681] |   bar() {
            [ 6681] |     foo() {
   0.593 us [ 6681] |       strncpy();
   1.317 us [ 6681] |     } /* foo */
            [ 6681] |     foo() {
   0.700 us [ 6681] |       strncpy();
   1.336 us [ 6681] |     } /* foo */
   3.723 us [ 6681] |   } /* bar */
   8.063 us [ 6681] | } /* main */
""")
