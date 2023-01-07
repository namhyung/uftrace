#!/usr/bin/env python

from runtest import TestBase

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

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-Z 30 -T bar@size=1000'
