#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'lib', """
# DURATION    TID     FUNCTION
            [17459] | lib_b() {
   6.911 us [17459] |   lib_c();
   8.279 us [17459] | } /* lib_b */
""")

    def build(self, cflags='', ldflags=''):
        import os
        import subprocess as sp

        if self.lang not in TestBase.supported_lang:
#            print("%s: unsupported language: %s" % (self.name, self.lang))
            return TestBase.TEST_UNSUPP_LANG

        lang = TestBase.supported_lang[self.lang]
        prog = 't-' + self.name

        build_cflags  = ' '.join([self.cflags, cflags, \
                                  os.getenv(lang['flags'], '')])
        build_ldflags = ' '.join([self.ldflags, ldflags, \
                                  os.getenv('LDFLAGS', '')])

        lib_cflags = build_cflags + ' -shared -fPIC'

        # build libabc_test_lib.so library
        build_cmd = '%s -o libabc_test_lib.so %s s-lib.c %s' % \
                    (lang['cc'], lib_cflags, build_ldflags)

#        print("build command for library: %s" % build_cmd)
        if sp.call(build_cmd.split(), stdout=sp.PIPE) < 0:
            return TestBase.TEST_BUILD_FAIL

        exe_ldflags = build_ldflags + ' -Wl,-rpath,"$ORIGIN" -L. -labc_test_lib'

        build_cmd = '%s -o %s s-libmain.c %s' % \
                    (lang['cc'], prog, exe_ldflags)

#        print("build command for executable: %s" % build_cmd)
        if sp.call(build_cmd.split(), stdout=sp.PIPE) < 0:
            return TestBase.TEST_BUILD_FAIL
        return 0

    def sort(self, output, ignore_children=False):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and header
            if ln.strip() == '' or ln.startswith('#'):
                continue
            func = ln.split('|', 1)[-1]
            result.append(func)
        return '\n'.join(result)

    def pre(self):
        record_cmd = '%s record --force -d %s %s' % (TestBase.ftrace, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s -F lib_b@libabc_test' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
