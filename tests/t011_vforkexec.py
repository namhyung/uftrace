#!/usr/bin/env python

import re, os
import subprocess as sp
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'vforkexec', """
# DURATION    TID     FUNCTION
  77.595 us [30337] | __cxa_atexit();
            [30337] | main() {
            [30337] |   vfork() {
  85.943 us [30338] |   } /* vfork */
            [30338] |   child() {
  35.030 us [30338] |     readlink();
   1.420 us [30338] |     strrchr();
            [30338] |     execl() {
 191.488 us [30337] |     } /* execl */   <--- ???
 232.328 us [30337] |   } /* child */
  74.979 us [30338] | <4004d0>();      <---------------------+
            [30338] | _start() {                             |
            [30338] |   waitpid() {                          |
            [30338] |     vfork() {                          |
            [30338] |       __cxa_atexit() {             should be
   5.880 us [30338] |         <400480>();                 ignored
   6.834 us [30338] |       } /* __cxa_atexit */             |
   7.444 us [30338] |     } /* vfork */                      |
   8.076 us [30338] |   } /* waitpid */                      |
   8.830 us [30338] | } /* _start */   <---------------------+

ftrace stopped tracing with remaining functions
===============================================
task: 30337
[0] main

""")

    def build(self, cflags='', ldflags=''):
        if self.lang not in TestBase.supported_lang:
#            print("%s: unsupported language: %s" % (self.name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + self.name
        src  = 's-' + self.name + lang['ext']

        build_cflags  = ' '.join([self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, \
                                  os.getenv('LDFLAGS', '')])

        # build t-abc (to be exec-ed) first
        build_cmd = 'gcc -o t-abc %s s-abc.c %s' % (build_cflags, build_ldflags)
        if sp.call(build_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE) != 0:
            return TestBase.TEST_BUILD_FAILURE

        build_cmd = '%s -o %s %s %s %s' % \
                    (lang['cc'], prog, build_cflags, src, build_ldflags)

#        print("build command:", build_cmd)
        return sp.call(build_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)

    def sort(self, output):
        return TestBase.sort(self, output, True)
