#!/usr/bin/env python

from runtest import TestBase

# in this case, malloc() in ns2 was already filtered out,
# so 'trace-off' trigger cannot be fired and shows delete() and main exit.
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
   4.843 us [29826] |   operator new();
   1.846 us [29826] |   ns::ns1::foo::foo();
            [29826] |   ns::ns1::foo::bar() {
            [29826] |     ns::ns1::foo::bar1() {
            [29826] |       ns::ns1::foo::bar2() {
            [29826] |         ns::ns1::foo::bar3() {
   0.597 us [29826] |   operator new();
   0.410 us [29826] |   operator delete();
 143.705 us [29826] | } /* main */
""", sort='simple')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd  = 'replay'
        self.option  = "--disable -N 'ns2.*' -T 'operator new@trace-on' "
        self.option += "-T 'malloc@traceoff'"
