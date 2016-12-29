#!/usr/bin/env python

import re, os
import subprocess as sp
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'vforkexec', """
# DURATION    TID     FUNCTION
            [ 3122] | main() {
            [ 3122] |   vfork() {
            [ 3124] |   } /* vfork */
  61.715 us [ 3124] |   readlink();
   2.799 us [ 3124] |   strrchr();
   1.192 us [ 3124] |   strcpy();
            [ 3124] |   execl() {
            [ 3122] |   } /* vfork */
 549.064 us [ 3122] | } /* main */
            [ 3124] | main() {
            [ 3124] |   a() {
            [ 3124] |     b() {
            [ 3124] |       c() {
   1.655 us [ 3124] |         getpid();
   3.861 us [ 3124] |       } /* c */
   4.393 us [ 3124] |     } /* b */
   4.901 us [ 3124] |   } /* a */
  75.511 us [ 3124] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'abc', cflags, ldflags)
        ret += TestBase.build(self, self.name, cflags, ldflags)
        return ret

    def runcmd(self):
        return '%s -F main %s' % (TestBase.ftrace, 't-' + self.name)

    def fixup(self, cflags, result):
        r = result

        import platform
        if platform.machine().startswith('arm'):
            r = r.replace('readlink', """memset();
                                [ 3124] |   readlink""")

        return r
