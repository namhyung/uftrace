#!/usr/bin/env python3

import shutil

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'pltarg', result="""
# DURATION     TID     FUNCTION
   1.237 us [ 203479] | __monstartup();
   0.897 us [ 203479] | __cxa_atexit();
            [ 203479] | main() {
   4.886 us [ 203479] |   getenv();
   2.139 us [ 203479] |   malloc();
   1.017 us [ 203479] |   free();
  12.233 us [ 203479] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # test only if 'mold' linker is available
        if shutil.which('mold') is None:
            return TestBase.TEST_SKIP

        ldflags += " -fuse-ld=mold"
        return TestBase.build(self, name, cflags, ldflags)
