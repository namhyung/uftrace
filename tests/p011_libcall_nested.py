#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'libmain', """
# DURATION     TID     FUNCTION
            [ 12889] | __main__.<module>() {
            [ 12889] |   myfunc() {
            [ 12889] |     mymod.public_func() {
   0.444 us [ 12889] |       mymod.internal();
   0.307 us [ 12889] |       mymod.internal();
   3.965 us [ 12889] |     } /* mymod.public_func */
   6.477 us [ 12889] |   } /* myfunc */
 624.569 us [ 12889] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '--nest-libcall -N ^importlib'
