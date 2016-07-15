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
            return TestBase.TEST_BUILD_FAILURE

        build_cmd = '%s -o %s %s %s %s' % \
                    (lang['cc'], prog, build_cflags, src, build_ldflags)

#        print("build command:", build_cmd)
        return sp.call(build_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)

    def fixup(self, cflags, result):
        r = result
        f = cflags.split()

        if f[0] == '-pg':
            r = r.replace('execl() {', """execl() {
                                [ 3124] | __monstartup();
                                [ 3124] | __cxa_atexit();""")

        import platform
        if platform.machine().startswith('arm'):
            r = r.replace('readlink', """memset();
                                [ 3124] |   readlink""")

        return r
