#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
   0.508 us [  772] | __monstartup();
   0.425 us [  772] | __cxa_atexit();
            [  772] | main() {
            [  772] |   a() {
            [  772] |     b() {
            [  772] |       c() {
   0.419 us [  772] |         getpid();
   0.844 us [  772] |       }
   1.037 us [  772] |     }
   1.188 us [  772] |   }
   1.378 us [  772] | }
""")

    def setup(self):
        self.option = '--no-comment'
