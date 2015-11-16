#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [ 7102] | main() {
   2.697 us [ 7102] |   operator new();
   0.842 us [ 7102] |   ns::ns1::foo::foo();
            [ 7102] |   ns::ns1::foo::bar() {
            [ 7102] |     ns::ns1::foo::bar1() {
            [ 7102] |       ns::ns1::foo::bar2() {
   1.926 us [ 7102] |       } /* ns::ns1::foo::bar2 */
   2.169 us [ 7102] |     } /* ns::ns1::foo::bar1 */
   1.215 us [ 7102] |     free();
   3.897 us [ 7102] |   } /* ns::ns1::foo::bar */
   1.865 us [ 7102] |   operator delete();
   0.274 us [ 7102] |   operator new();
   0.115 us [ 7102] |   ns::ns2::foo::foo();
            [ 7102] |   ns::ns2::foo::bar() {
   1.566 us [ 7102] |   } /* ns::ns2::foo::bar */
   0.168 us [ 7102] |   operator delete();
  78.921 us [ 7102] | } /* main */
""")

    def pre(self):
        record_cmd = '%s record -f %s %s' % (TestBase.ftrace, TDIR, 't-namespace')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -f %s -N "bar3$" -Tns::ns2::foo::bar@depth=1' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    
