#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [12683] |   ns::ns2::foo::bar() {
            [12683] |     ns::ns2::foo::bar1() {
            [12683] |       ns::ns2::foo::bar2() {
            [12683] |         ns::ns2::foo::bar3() {
   1.067 us [12683] |           malloc();
   2.390 us [12683] |         } /* ns::ns2::foo::bar3 */
   3.197 us [12683] |       } /* ns::ns2::foo::bar2 */
   4.177 us [12683] |     } /* ns::ns2::foo::bar1 */
   0.695 us [12683] |     free();
 105.025 us [12683] |   } /* ns::ns2::foo::bar */
   0.602 us [12683] |   operator delete();
            [12683] | } /* main */
""", sort='simple')

    def setup(self):
        self.option = '--disable -T "ns::ns2::foo::bar@trace_on"'
