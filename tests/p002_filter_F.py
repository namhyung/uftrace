#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28142] | a() {
            [ 28142] |   b() {
            [ 28142] |     c() {
   0.753 us [ 28142] |       posix.getpid();
   1.430 us [ 28142] |     } /* c */
   1.915 us [ 28142] |   } /* b */
   2.405 us [ 28142] | } /* a */
""")

    def setup(self):
        self.option = '-F a'
