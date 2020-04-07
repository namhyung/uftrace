#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [ 3357] | main() {
   2.874 us [ 3357] |   operator new();
   3.115 us [ 3357] |   operator delete();
   0.456 us [ 3357] |   operator new();
   0.386 us [ 3357] |   ns::ns2::foo::foo();
            [ 3357] |   ns::ns2::foo::bar() {
            [ 3357] |     ns::ns2::foo::bar1() {
            [ 3357] |       ns::ns2::foo::bar2() {
            [ 3357] |         ns::ns2::foo::bar3() {
   0.346 us [ 3357] |           malloc();
   0.732 us [ 3357] |         } /* ns::ns2::foo::bar3 */
   0.847 us [ 3357] |       } /* ns::ns2::foo::bar2 */
   1.339 us [ 3357] |     } /* ns::ns2::foo::bar1 */
   0.411 us [ 3357] |     free();
   2.072 us [ 3357] |   } /* ns::ns2::foo::bar */
   0.311 us [ 3357] |   operator delete();
 105.160 us [ 3357] | } /* main */
""")

    def setup(self):
        self.option = '-N ".*ns1::.*"'
