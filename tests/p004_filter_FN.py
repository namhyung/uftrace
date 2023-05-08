#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28141] | a() {
            [ 28141] |   b() {
   1.430 us [ 28141] |     c();
   1.915 us [ 28141] |   } /* b */
   2.405 us [ 28141] | } /* a */
""")

    def setup(self):
        self.option = '-F a -N .getpid'
