#!/usr/bin/env python

import re, os
import subprocess as sp
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'forkexec', """
# DURATION    TID     FUNCTION
  79.003 us [29473] | __cxa_atexit();
            [29473] | main() {
  10.136 us [29473] |   readlink();
   1.100 us [29473] |   strrchr();
 112.028 us [29473] |   fork();
            [29473] |   waitpid() {
  75.782 us [29474] | <4004d0>();     <-----------------------+
            [29474] | exit() {                                |
            [29474] |   __libc_start_main() {                 |
            [29474] |     __monstartup() {                    |
            [29474] |       mcount() {                    currently
   5.597 us [29474] |         <400480>();                  ignored
   6.507 us [29474] |       } /* mcount */                    |
   7.106 us [29474] |     } /* __monstartup */                |
   7.743 us [29474] |   } /* __libc_start_main */             |
   8.500 us [29474] | } /* exit */                            |
 328.763 us [29474] |   } /* fork */                          |
            [29474] |   execl() {      <----------------------+
   1.834 ms [29473] |   } /* waitpid */
   1.977 ms [29473] | } /* main */

ftrace stopped tracing with remaining functions
===============================================
task: 29474
[0] execl

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
            return TestBase.TEST_BUILD_FAIL

        build_cmd = '%s -o %s %s %s %s' % \
                    (lang['cc'], prog, build_cflags, src, build_ldflags)

#        print("build command:", build_cmd)
        return sp.call(build_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)

    def sort(self, output):
        return TestBase.sort(self, output, True)
