#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [14470] | ns::ns1::foo::bar() {
            [14470] |   ns::ns1::foo::bar1() {
            [14470] |     ns::ns1::foo::bar2() {
            [14470] |       ns::ns1::foo::bar3() {
   4.039 us [14470] |         malloc();
   5.471 us [14470] |       } /* ns::ns1::foo::bar3 */
   6.145 us [14470] |     } /* ns::ns1::foo::bar2 */
   6.858 us [14470] |   } /* ns::ns1::foo::bar1 */
   2.207 us [14470] |   free();
 100.290 us [14470] | } /* ns::ns1::foo::bar */
""", sort='simple')

    def setup(self):
        self.option = '-F "ns::ns1::foo::bar"'
