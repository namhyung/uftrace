#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'malloc-fork', ldflags='-ldl', result="""
# DURATION    TID     FUNCTION
            [22300] | __cxa_atexit() {
   1.328 us [22300] | } /* __cxa_atexit */
            [22300] | malloc() {
   0.200 us [22300] | } /* malloc */
            [22300] | main() {
            [22300] |   fork() {
 108.998 us [22300] |   } /* fork */
            [22300] |   malloc() {
   0.164 us [22300] |   } /* malloc */
            [22300] |   free() {
   0.100 us [22300] |   } /* free */
 123.077 us [22300] | } /* main */
            [22304] |   } /* fork */
            [22304] |   malloc() {
   0.128 us [22304] |   } /* malloc */
            [22304] |   free() {
   0.081 us [22304] |   } /* free */
            [22304] | } /* main */
""")

    def setup(self):
        self.option = '--no-merge'
