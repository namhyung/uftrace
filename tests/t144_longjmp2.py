#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'longjmp2', """
# DURATION    TID     FUNCTION
   1.517 us [ 3024] | __monstartup();
   0.971 us [ 3024] | __cxa_atexit();
            [ 3024] | main() {
   3.588 us [ 3024] |   _setjmp();
            [ 3024] |   foo() {
            [ 3024] |     longjmp() {
   1.637 us [ 3024] |   } /* _setjmp */
            [ 3024] |   bar() {
            [ 3024] |     baz() {
            [ 3024] |       longjmp() {
   0.671 us [ 3024] |   } /* _setjmp */
   7.291 us [ 3024] | } /* main */
""")
