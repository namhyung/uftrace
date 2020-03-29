#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [ 4629] | main() {
            [ 4629] |   alloc1() {
            [ 4629] |     alloc2() {
   4.999 us [ 4629] |       alloc3();
   5.360 us [ 4629] |     } /* alloc2 */
   5.811 us [ 4629] |   } /* alloc1 */
            [ 4629] |   free1() {
            [ 4629] |     free2() {
            [ 4629] |       free3() {
            [ 4629] |         free4() {
            [ 4629] |           free5() {
   1.057 us [ 4629] |             free();
   1.563 us [ 4629] |           } /* free5 */
   1.817 us [ 4629] |         } /* free4 */
   2.072 us [ 4629] |       } /* free3 */
   2.323 us [ 4629] |     } /* free2 */
   2.580 us [ 4629] |   } /* free1 */
  78.021 us [ 4629] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-F "main" -F "alloc3@depth=1"'
