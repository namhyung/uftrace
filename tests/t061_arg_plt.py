#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'pltarg', result="""
# DURATION    TID     FUNCTION
   1.237 us [ 3479] | __monstartup();
   0.897 us [ 3479] | __cxa_atexit();
            [ 3479] | main() {
   4.886 us [ 3479] |   getenv("HOME");
   2.079 us [ 3479] |   atoi("100");
   2.139 us [ 3479] |   malloc(100);
   1.017 us [ 3479] |   free();
  12.233 us [ 3479] | } /* main */
""")

    def setup(self):
        self.option = '-A "getenv|atoi@arg1/s" -A malloc@arg1'
        self.exearg = 't-' + self.name + ' 100'

    def fixup(self, cflags, result):
        # for some reason, ARM eats up atoi()
        return result.replace('   2.079 us [ 3479] |   atoi("100");\n', '')
