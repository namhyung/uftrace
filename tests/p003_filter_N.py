#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28143] | __main__.<module>() {
            [ 28143] |   a() {
   1.915 us [ 28143] |     b();
   2.405 us [ 28143] |   } /* a */
   3.005 us [ 28143] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '-N c'
