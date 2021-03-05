#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
  61.419 us [ 1817] | ns::ns1::foo::foo();
            [ 1817] | ns::ns1::foo::bar() {
   2.585 us [ 1817] |   ns::ns1::foo::bar1();
   1.303 us [ 1817] |   free();
   4.863 us [ 1817] | } /* ns::ns1::foo::bar */
""", sort='simple')

    def setup(self):
        self.option = '-F "ns1::.*" -N "bar2$"'
