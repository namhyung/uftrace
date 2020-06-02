#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dwarf1', """
# DURATION     TID     FUNCTION
            [ 29831] | main() {
   0.495 us [ 29831] |   foo(-1, 32768) = 32767;
            [ 29831] |   bar("string argument", 'c', 0.000010, &null) {
   0.660 us [ 29831] |     null("NULL");
 442.163 us [ 29831] |   } = -1.000000; /* bar */
            [ 29831] |   baz(ONE) {
   0.323 us [ 29831] |     foo(1, -1) = 0;
   1.291 us [ 29831] |   } /* baz */
 449.927 us [ 29831] | } = 0; /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A . -R. -F main'
