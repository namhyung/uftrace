#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
  53.511 us [ 6624] | ns::ns1::foo::foo();
            [ 6624] | ns::ns1::foo::bar2() {
            [ 6624] |   ns::ns1::foo::bar3() {
   1.607 us [ 6624] |     malloc();
   2.520 us [ 6624] |   } /* ns::ns1::foo::bar3 */
   2.982 us [ 6624] | } /* ns::ns1::foo::bar2 */
   0.174 us [ 6624] | ns::ns2::foo::foo();
            [ 6624] | ns::ns2::foo::bar2() {
            [ 6624] |   ns::ns2::foo::bar3() {
   0.365 us [ 6624] |     malloc();
   0.834 us [ 6624] |   } /* ns::ns2::foo::bar3 */
   1.200 us [ 6624] | } /* ns::ns2::foo::bar2 */
""", sort='simple')

    def setup(self):
        self.option = '--disable -F ".*foo::foo" -T .foo::foo@trace_on -F .bar2'
