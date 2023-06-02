#!/usr/bin/env python

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'libmain', """
# DURATION     TID     FUNCTION
            [ 12778] | __main__.<module>() {
   8.153 ms [ 12778] |   mymod.<module>();
            [ 12778] |   myfunc() {
            [ 12778] |     mymod.public_func() {
  22.748 us [ 12778] |       mymod.internal();
   6.878 us [ 12778] |       mymod.internal();
  32.405 us [ 12778] |     } /* mymod.public_func */
  35.086 us [ 12778] |   } /* myfunc */
   8.787 ms [ 12778] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '--no-libcall'
