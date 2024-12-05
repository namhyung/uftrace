#!/usr/bin/env python3

import os
import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dlopen2', lang="C++", cflags='-g', result="""
# DURATION     TID      FUNCTION
            [1358278] | main(1, 0xADDR) {
   1.004  s [1358278] |   dlopen("./libbaz.so", RTLD_LAZY) = 0xADDR;
  11.847 us [1358278] |   dlsym(0xADDR, "create") = &create;
            [1358278] |   create() {
            [1358278] |     Child::Child(0xADDR) {
   7.422 us [1358278] |       Parent::Parent(0xADDR);
   8.859 us [1358278] |     } /* Child::Child */
  10.168 us [1358278] |   } = 0xADDR; /* create */
  99.308 us [1358278] |   Child::func(0xADDR, 1) = 100;
  36.109 us [1358278] |   dlclose(0xADDR) = 0;
   2.012  s [1358278] | } = 0; /* main */
""")
        os.environ['LD_LIBRARY_PATH'] = "."

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP
        # we want to test auto-args from DWARF
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP

        if TestBase.build_libfoo(self, 'bar', cflags, ldflags) != 0:
            return TestBase.TEST_BUILD_FAIL
        if TestBase.build_libfoo(self, 'baz', cflags, ldflags + ' -L. -lbar') != 0:
            return TestBase.TEST_BUILD_FAIL
        return TestBase.build_libmain(self, name, 's-dlopen2.cpp', ['libdl.so'],
                                      cflags, ldflags)

    def setup(self):
        self.option = '-F main -a'

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'0x[0-9a-f]+', '0xADDR', line)
            result.append(func)

        return '\n'.join(result)

    def fixup(self, cflags, result):
        # GCC seems to optimize out the empty Parent::Parent().
        return result.replace("""
            [1358278] |     Child::Child(0xADDR) {
   7.422 us [1358278] |       Parent::Parent(0xADDR);
   8.859 us [1358278] |     } /* Child::Child */""", """
            [1358278] |     Child::Child(0xADDR);""")
