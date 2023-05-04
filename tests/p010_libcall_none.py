#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'libmain', """
# DURATION     TID     FUNCTION
            [ 12778] | __main__.<module>() {
   6.257 us [ 12778] |   myfunc();
 593.772 us [ 12778] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '--no-libcall'
