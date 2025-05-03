#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'arg', """
# DURATION     TID      FUNCTION
            [  26654] | bar(1, "b") {
   0.325 us [  26654] |   strcmp("b", "b") = 0;
  80.824 us [  26654] | } = 0; /* bar */
            [  26654] | bar(0, "a") {
   0.122 us [  26654] |   strcmp("a", "a") = 0;
   0.389 us [  26654] | } = 0; /* bar */
""", cflags='-g', sort='simple')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-a -T "bar@filter,if:arg1 != 2"'
