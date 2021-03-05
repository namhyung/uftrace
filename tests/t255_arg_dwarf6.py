#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dwarf6', """
# DURATION     TID     FUNCTION
            [152673] | main() {
  83.549 us [152673] |   addString(" uftrace "s, "test") = " uftrace test"s;
   4.597 us [152673] |   addItem(vector{...}, 0) = vector{...};
 116.117 us [152673] | } /* main */
""", lang='C++', cflags='-g -std=c++11')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-F main -N ^std -A ^add -R ^add'
