#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dwarf7', """
# DURATION     TID     FUNCTION
            [1279330] | main() {
   0.166 us [1279330] |   compare_iters(__normal_iterator{...}, __normal_iterator{...}) = 0;
   5.959 us [1279330] | } = 0; /* main */
""", lang='C++', cflags='-g -std=c++11')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-a -C compare_iters'
