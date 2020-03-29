#!/usr/bin/env python

from runtest import TestBase

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
   0.317 us [29826] |   ns::ns2::foo::foo();
            [29826] |   ns::ns2::foo::bar() {
            [29826] |     ns::ns2::foo::bar1() {
            [29826] |       ns::ns2::foo::bar2() {
            [29826] |         ns::ns2::foo::bar3() {
""", sort='simple')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = "replay"
        self.option = "--disable -T 'operator new@trace_on' -T 'malloc@trace_off'"
