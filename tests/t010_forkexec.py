#!/usr/bin/env python

import re, os
import subprocess as sp
from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'forkexec', """
# DURATION    TID     FUNCTION
            [ 9874] | main() {
  19.427 us [ 9874] |   readlink();
   1.841 us [ 9874] |   strrchr();
   0.911 us [ 9874] |   strcpy();
 142.145 us [ 9874] |   fork();
            [ 9874] |   waitpid() {
 473.298 us [ 9875] |   } /* fork */
            [ 9875] |   execl() {
            [ 9875] | main() {
   1.828 us [ 9875] |   atoi();
            [ 9875] |   a() {
            [ 9875] |     b() {
            [ 9875] |       c() {
   0.976 us [ 9875] |         getpid();
   1.992 us [ 9875] |       } /* c */
   2.828 us [ 9875] |     } /* b */
   3.658 us [ 9875] |   } /* a */
   7.713 us [ 9875] | } /* main */
   2.515 ms [ 9874] |   } /* waitpid */
   2.708 ms [ 9874] | } /* main */

""")

    def build(self, cflags='', ldflags=''):
        if self.lang not in TestBase.supported_lang:
#            print("%s: unsupported language: %s" % (self.name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + self.name
        src  = 's-' + self.name + lang['ext']

        build_cflags  = ' '.join(TestBase.default_cflags + [self.cflags, cflags, \
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

    def fixup(self, cflags, result):
        r = result
        f = cflags.split()

        if f[0] == '-pg':
            r = r.replace('execl() {', """execl() {
                                [ 9875] | __monstartup();
                                [ 9875] | __cxa_atexit();""")

        import platform
        if platform.machine().startswith('arm'):
            r = r.replace('readlink', """memset();
                                [ 9874] |   readlink""")

        return r
