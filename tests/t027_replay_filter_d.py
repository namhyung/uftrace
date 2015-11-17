#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [ 4629] | main() {
            [ 4629] |   alloc1() {
            [ 4629] |     alloc2() {
            [ 4629] |       alloc3() {
   4.999 us [ 4629] |       } /* alloc3 */
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

    def pre(self):
        record_cmd = '%s record -f %s %s' % (TestBase.ftrace, TDIR, 't-allocfree')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -F "main,alloc3@depth=1" -f %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
