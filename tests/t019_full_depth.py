#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [30388] | main() {
            [30388] |   alloc1() {
   7.794 us [30388] |     alloc2();
   9.137 us [30388] |   } /* alloc1 */
            [30388] |   free1() {
   3.621 us [30388] |     free2();
   4.499 us [30388] |   } /* free1 */
 120.407 us [30388] | } /* main */
""")

    def setup(self):
        self.option = '-D3'
