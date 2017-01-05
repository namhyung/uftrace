#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

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

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.ftrace, TDIR, 't-namespace')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s --disable -T "operator new@traceon" -T "malloc@traceoff"' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
