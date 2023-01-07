#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

SIZE = 100

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg', """
# DURATION     TID     FUNCTION
            [162500] | main() {
  12.486 us [162500] |   foo();
   0.505 us [162500] |   many();
            [162500] |   pass() {
   0.283 us [162500] |     check();
   1.449 us [162500] |   } /* pass */
  18.478 us [162500] | } /* main */
""")

    def prerun(self, timeout):
        # run 'readelf' tool to read exact symbol size of 'bar' (the smallest one)
        # and save its 'size + 1' to exclude the function
        try:
            output = sp.check_output(['readelf', '-s', 't-arg'])
        except:
            return TestBase.TEST_SKIP

        for ln in output.decode(errors='ignore').split('\n'):
            # Num: Value Size Type Bind Vis Ndx Name
            syms = ln.split()
            if len(syms) < 8:
                continue
            if syms[7] == 'bar':
                global SIZE
                SIZE = int(syms[2]) + 1
                break
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'live'
        self.option = '-Z %d' % SIZE
        self.exearg = 't-' + self.name
