#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
  backtrace [ 4629] | /* [ 0] main */
  backtrace [ 4629] | /* [ 1] alloc1 */
  backtrace [ 4629] | /* [ 2] alloc2 */
  backtrace [ 4629] | /* [ 3] alloc3 */
            [ 4629] | alloc4() {
            [ 4629] |   alloc5() {
   2.020 us [ 4629] |     malloc();
   4.334 us [ 4629] |   } /* alloc5 */
   4.671 us [ 4629] | } /* alloc4 */
""", sort='simple')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-T "alloc4@filter,backtrace"'
