#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'libmain', """
# DURATION     TID     FUNCTION
            [ 12698] | __main__.<module>() {
 672.937 us [ 12698] |   importlib._bootstrap._find_and_load();
            [ 12698] |   myfunc() {
   2.986 us [ 12698] |     mymod.public_func();
   5.510 us [ 12698] |   } /* myfunc */
 687.635 us [ 12698] | } /* __main__.<module> */
""")
