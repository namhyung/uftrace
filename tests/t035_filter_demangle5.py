#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
  66.323 us [ 1845] | ns::ns1::foo::foo();
            [ 1845] | ns::ns1::foo::bar() {
            [ 1845] |   ns::ns1::foo::bar1() {
            [ 1845] |     ns::ns1::foo::bar2() {
            [ 1845] |       ns::ns1::foo::bar3() {
   1.759 us [ 1845] |         malloc();
   2.656 us [ 1845] |       } /* ns::ns1::foo::bar3 */
   2.996 us [ 1845] |     } /* ns::ns1::foo::bar2 */
   3.346 us [ 1845] |   } /* ns::ns1::foo::bar1 */
   1.367 us [ 1845] |   free();
   5.499 us [ 1845] | } /* ns::ns1::foo::bar */
            [ 1845] | ns::ns2::foo::bar2() {
            [ 1845] |   ns::ns2::foo::bar3() {
   0.450 us [ 1845] |     malloc();
   0.930 us [ 1845] |   } /* ns::ns2::foo::bar3 */
   1.393 us [ 1845] | } /* ns::ns2::foo::bar2 */
""", sort='simple')

    # test whether filter option preserves the ordering
    def setup(self):
        self.option = '-F "ns1::.*" -N "bar2$" -F "bar2$"'
