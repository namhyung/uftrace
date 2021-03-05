#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [ 5943] | main(1) {
   3.800 us [ 5943] |   operator new();
   0.310 us [ 5943] |   ns::ns1::foo::foo();
            [ 5943] |   ns::ns1::foo::bar() {
   2.523 us [ 5943] |     ns::ns1::foo::bar1();
   1.627 us [ 5943] |     free();
   5.152 us [ 5943] |   } /* ns::ns1::foo::bar */
   1.240 us [ 5943] |   operator delete();
   0.203 us [ 5943] |   operator new();
   0.102 us [ 5943] |   ns::ns2::foo::foo();
            [ 5943] |   ns::ns2::foo::bar() {
   0.860 us [ 5943] |     ns::ns2::foo::bar1();
   0.215 us [ 5943] |     free();
   1.895 us [ 5943] |   } /* ns::ns2::foo::bar */
   0.237 us [ 5943] |   operator delete();
  21.882 us [ 5943] | } /* main */
""", sort='simple')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-T main@filter,depth=3,arg1'
