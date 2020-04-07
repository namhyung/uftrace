#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [30192] | main() {
   3.210 us [30192] |   operator new();
   1.435 us [30192] |   ns::ns1::foo::foo();
            [30192] |   ns::ns1::foo::bar() {
            [30192] |     ns::ns1::foo::bar1() {
            [30192] |       ns::ns2::foo::bar2() {
            [30192] |         ns::ns2::foo::bar3() {
   0.988 us [30192] |           malloc();
   1.735 us [30192] |         } /* ns::ns2::foo::bar3 */
   2.342 us [30192] |       } /* ns::ns2::foo::bar2 */
  14.366 us [30192] |     } /* ns::ns2::foo::bar1 */
   0.472 us [30192] |     free();
  15.807 us [30192] |   } /* ns::ns2::foo::bar */
   0.316 us [30192] |   operator delete();
 107.604 us [30192] | } /* main */
""")

    def setup(self):
        self.option  = '-T "ns::ns1::foo::bar2@trace_off" '
        self.option += '-T "ns::ns2::foo::bar2@trace-on"'
