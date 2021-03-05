#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'unroll', """
# DURATION    TID     FUNCTION
            [ 72208] | main() {
   0.252 us [ 72208] |   big();
   1.802 us [ 72208] | } /* main */

""")

    def build(self, name, cflags='', ldflags=''):
        cflags = cflags.replace('-pg', '')
        cflags = cflags.replace('-finstrument-functions', '')
        cflags += ' -funroll-loops'
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-P. -Z 100'
