#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-mixed', result="""
# DURATION    TID     FUNCTION
            [18277] | main() {
   0.371 ms [18277] |   mixed_add(-1, 0.200000);
   0.118 ms [18277] |   mixed_sub(0x400000, 2048);
   0.711 ms [18277] |   mixed_mul(-3.000000, 80000000000);
   0.923 ms [18277] |   mixed_div(4, -0.000002);
   1.257 ms [18277] |   mixed_str("argument", 0.000000);
   4.891 ms [18277] | } /* main */
""")

    def prerun(self, timeout):
        if TestBase.get_elf_machine(self) == 'i386':
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option  = '-A "mixed_add@arg1/i32%rdi,fparg1/32%xmm0" '
        self.option += '-A "mixed_sub@arg1/x%rdi,arg2%rsi" '
        self.option += '-A "mixed_mul@fparg1%xmm0,arg1/i64" '
        self.option += '-A "mixed_div@arg1/i64,fparg1/80%stack+1" '
        self.option += '-A "mixed_str@arg1/s%rdi,fparg1%xmm0"'

        if TestBase.get_elf_machine(self) == 'arm':
            self.option = self.option.replace('%rdi', '%r0')
            self.option = self.option.replace('%rsi', '%r1')
            self.option = self.option.replace('32%xmm0', '32%s0')
            self.option = self.option.replace('%xmm0', '%d0')
            self.option = self.option.replace('fparg1/80%stack+1', 'fparg1/80')
