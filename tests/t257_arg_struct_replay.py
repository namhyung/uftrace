#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'struct', """
# DURATION     TID     FUNCTION
            [ 54277] | main() {
 207.329 us [ 54277] |   foo(Option{...}, StringRef{}, 44, 55, 66);
 208.750 us [ 54277] | } = 0; /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-a --no-libcall'
