#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'nest-libcall', """1
# DURATION     TID        MODULE NAME   FUNCTION
            [ 26884]   t-nest-libcall | main() {
            [ 26884]   t-nest-libcall |   lib_a@libabc_test_lib.so() {
   2.320 us [ 26884] libabc_test_lib. |     getpid@libc-2.26.so();
   8.884 us [ 26884]   t-nest-libcall |   } /* lib_a@libabc_test_lib.so */
            [ 26884]   t-nest-libcall |   foo@libfoo.so() {
   0.880 us [ 26884]        libfoo.so |     AAA::bar@libfoo.so();
   2.423 us [ 26884]   t-nest-libcall |   } /* foo@libfoo.so */
  13.722 us [ 26884]   t-nest-libcall | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        if TestBase.build_libabc(self, '', '') != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'foo', '', '') != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-nest-libcall.c',
                                      ['libabc_test_lib.so', 'libfoo.so'],
                                      cflags, ldflags)

    def setup(self):
        self.option = "--nest-libcall --libname -f +module"

    def fixup(self, cflags, result):
        import re
        import subprocess as sp

        #
        # use `ldd --version` to get libc version
        #

        # $ ldd --version
        # ldd (GNU libc) 2.26    <-- use this
        # Copyright (C) 2017 Free Software Foundation, Inc.
        # ...
        v = sp.check_output(["ldd", "--version"]).decode(errors='ignore')
        ver = v.split('\n')[0].split(') ')[1]
        ver.strip()

        return re.sub("libc-[\d.]+.so", "libc-%s.so" % ver, result)
