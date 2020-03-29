#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', """
# DURATION    TID     FUNCTION
            [ 6565] | main() {
   2.234 us [ 6565] |   operator new();
   0.897 us [ 6565] |   ns::ns1::foo::foo();
            [ 6565] |   ns::ns1::foo::bar() {
            [ 6565] |     ns::ns1::foo::bar1() {
            [ 6565] |       ns::ns1::foo::bar2() {
            [ 6565] |         ns::ns1::foo::bar3() {
            [ 6565] |           /* linux:task-exit */

uftrace stopped tracing with remaining functions
================================================
task: 6565
[4] ns::ns1::foo::bar3
[3] ns::ns1::foo::bar2
[2] ns::ns1::foo::bar1
[1] ns::ns1::foo::bar
[0] main
""", lang='C++')

    def setup(self):
        self.option = '-F main -T ns::ns1::foo::bar3@finish'

    def fixup(self, cflags, result):
        return result.replace("""ns::ns1::foo::bar3() {
            [ 6565] |           /* linux:task-exit */""",
                                "ns::ns1::foo::bar3() {")
