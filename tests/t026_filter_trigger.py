#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [  767] | main() {
            [  767] |   alloc1() {
            [  767] |     alloc2() {
   4.223 us [  767] |       alloc3();
   4.848 us [  767] |     } /* alloc2 */
   5.417 us [  767] |   } /* alloc1 */
            [  767] |   free1() {
            [  767] |     free2() {
            [  767] |       free3() {
            [  767] |         free4() {
            [  767] |           free5() {
   1.104 us [  767] |             free();
   1.974 us [  767] |           } /* free5 */
   2.289 us [  767] |         } /* free4 */
   2.577 us [  767] |       } /* free3 */
   2.857 us [  767] |     } /* free2 */
   3.188 us [  767] |   } /* free1 */
  66.699 us [  767] | } /* main */
""")

    def setup(self):
        self.option = '-F "main" -F "alloc3@depth=1"'
