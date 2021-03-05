#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# DURATION     TID     FUNCTION
            [ 73755] | main() {
   0.236 us [ 73755] |   foo();
            [ 73755] |   sighandler() {
   0.144 us [ 73755] |     bar();
   0.734 us [ 73755] |   } /* sighandler */
   0.117 us [ 73755] |   foo();
  18.227 us [ 73755] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '--no-libcall'
