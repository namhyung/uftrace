#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 30217] | main() {
            [ 30217] |   a() {
            [ 30217] |     b() {
   2.500 us [ 30217] |       getpid();
   8.600 us [ 30217] |     } /* b */
  11.500 us [ 30217] |   } /* a */
  14.500 us [ 30217] | } /* main */
""")

    def setup(self):
        self.option = '-T c@hide'
