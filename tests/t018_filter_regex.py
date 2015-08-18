#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
            [11583] | alloc1() {
            [11583] |   alloc2() {
            [11583] |     alloc3() {
            [11583] |       alloc4() {
   2.909 us [11583] |         alloc5();
   3.652 us [11583] |       } /* alloc4 */
   4.239 us [11583] |     } /* alloc3 */
   5.016 us [11583] |   } /* alloc2 */
 104.119 us [11583] | } /* alloc1 */
""")

    def runcmd(self):
        return '%s -F "^alloc.*$" %s' % (TestBase.ftrace, 't-allocfree')
