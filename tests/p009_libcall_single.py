#!/usr/bin/env python3

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'libmain', """
# DURATION     TID     FUNCTION
            [ 12698] | __main__.<module>() {
            [ 12698] |   myfunc() {
            [ 12698] |     mymod.public_func() {
            [ 12698] |       mymod.internal() {
  17.354 us [ 12698] |         json.dumps();
  21.809 us [ 12698] |       } /* mymod.internal */
            [ 12698] |       mymod.internal() {
   6.099 us [ 12698] |         json.dumps();
   7.196 us [ 12698] |       } /* mymod.internal */
  31.716 us [ 12698] |     } /* mymod.public_func */
  34.551 us [ 12698] |   } /* myfunc */
   8.932 ms [ 12698] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '-N ^importlib'
