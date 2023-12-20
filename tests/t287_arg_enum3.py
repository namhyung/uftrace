#!/usr/bin/env python3

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'enum2', result="""
# DURATION     TID     FUNCTION
            [ 57041] | main() {
   0.535 us [ 57041] |   foo(memory_order_mask);
   0.109 us [ 57041] |   foo(memory_order_modifier_mask);
   0.069 us [ 57041] |   foo(memory_order_hle_acquire);
   0.068 us [ 57041] |   foo(memory_order_hle_release);
   1.783 us [ 57041] | } = 0; /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not "dwarf" in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-F main -a'
