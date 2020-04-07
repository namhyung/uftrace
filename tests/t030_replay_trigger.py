#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [12561] | main() {
            [12561] |   alloc1() {
   4.499 us [12561] |     alloc2();
   4.998 us [12561] |   } /* alloc1 */
            [12561] |   free1() {
  backtrace [12561] | /* [ 0] main */
  backtrace [12561] | /* [ 1] free1 */
   3.905 us [12561] |     free2();
   4.392 us [12561] |   } /* free1 */
  10.380 us [12561] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-T "alloc1@depth=2" -T "free2@depth=1,backtrace"'
