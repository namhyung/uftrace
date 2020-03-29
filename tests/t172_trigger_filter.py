#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [ 5908] | main() {
   7.545 us [ 5908] |   operator new();
   0.377 us [ 5908] |   ns::ns1::foo::foo();
            [ 5908] |   ns::ns1::foo::bar() {
   2.694 us [ 5908] |     ns::ns1::foo::bar1();
   1.834 us [ 5908] |     free();
   5.574 us [ 5908] |   } /* ns::ns1::foo::bar */
   1.540 us [ 5908] |   operator delete();
   0.154 us [ 5908] |   operator new();
   0.177 us [ 5908] |   operator delete();
  25.925 us [ 5908] | } /* main */
""")

    def setup(self):
        self.option = '-T main@filter,depth=3 -T ^ns::ns2@notrace'
