#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-float', result="""
# DURATION    TID     FUNCTION
            [18276] | main() {
   0.371 ms [18276] |   float_add(-0.100000, 0.200000) = 0.100000;
   0.118 ms [18276] |   float_sub(0.100000, 0.200000) = -0.100000;
   0.711 ms [18276] |   float_mul(300.000000, 400.000000) = 120000.000000;
   0.923 ms [18276] |   float_div(40000000000.000000, -0.020000) = -2000000000000.000000;
   3.281 ms [18276] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-A "float_add@fparg1/32,fparg2/32" -R "float_add@retval/f32" '
        self.option += '-A "float_sub@fparg1/32,fparg2"    -R "float_sub@retval/f32" '
        self.option += '-A "float_mul@fparg1/64,fparg2/32" -R "float_mul@retval/f64" '
        self.option += '-A "float_div@fparg1,fparg2"       -R "float_div@retval/f"'

        if TestBase.is_32bit(self):
            # argument count follows the size of type
            self.option = self.option.replace('float_mul@fparg1/64,fparg2/32',
                                              'float_mul@fparg1/64,fparg3/32')
            self.option = self.option.replace('float_div@fparg1,fparg2',
                                              'float_div@fparg1/64,fparg3/64')
