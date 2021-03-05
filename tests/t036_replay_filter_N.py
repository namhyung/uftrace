#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [ 7102] | main() {
   2.697 us [ 7102] |   operator new();
   0.842 us [ 7102] |   ns::ns1::foo::foo();
            [ 7102] |   ns::ns1::foo::bar() {
            [ 7102] |     ns::ns1::foo::bar1() {
   1.926 us [ 7102] |       ns::ns1::foo::bar2();
   2.169 us [ 7102] |     } /* ns::ns1::foo::bar1 */
   1.215 us [ 7102] |     free();
   3.897 us [ 7102] |   } /* ns::ns1::foo::bar */
   1.865 us [ 7102] |   operator delete();
   0.274 us [ 7102] |   operator new();
   0.115 us [ 7102] |   ns::ns2::foo::foo();
   1.566 us [ 7102] |   ns::ns2::foo::bar();
   0.168 us [ 7102] |   operator delete();
  78.921 us [ 7102] | } /* main */
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'replay'
        self.option = '-N "bar3$" -Tns::ns2::foo::bar@depth=1'
