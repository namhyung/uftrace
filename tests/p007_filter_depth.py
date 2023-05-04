#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28142] | __main__.<module>() {
            [ 28142] |   a() {
   1.430 us [ 28142] |     b();
   1.915 us [ 28142] |   } /* a */
   2.405 us [ 28142] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '-D 3'
