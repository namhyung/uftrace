#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg', """
# DURATION     TID      FUNCTION
            [ 740577] | foo() {
            [ 740577] |   bar() {
   0.700 us [ 740577] |     strcmp();
 165.434 us [ 740577] |   } /* bar */
 166.700 us [ 740577] | } /* foo */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-F "foo@if:arg1==3" '
        self.option += '-N "bar@if:arg1 <2" '
