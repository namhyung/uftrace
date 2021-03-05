#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [ 4629] | alloc3() {
   4.671 us [ 4629] |   alloc4();
   4.999 us [ 4629] | } /* alloc3 */
            [ 4629] | free1() {
            [ 4629] |   free2() {
            [ 4629] |     free5() {
   1.057 us [ 4629] |       free();
   1.563 us [ 4629] |     } /* free5 */
   2.323 us [ 4629] |   } /* free2 */
   2.580 us [ 4629] | } /* free1 */
""", sort='simple')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-F alloc3 -D2 -F "free[15]"'
