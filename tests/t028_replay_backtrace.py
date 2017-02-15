#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

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

    def pre(self):
        record_cmd = '%s --no-pager record -d %s %s' % (TestBase.ftrace, TDIR, 't-allocfree')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -F "alloc4@backtrace" -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
