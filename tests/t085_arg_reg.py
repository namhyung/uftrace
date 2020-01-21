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

    def pre(self):
        if TestBase.get_elf_machine(self) == 'i386':
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def runcmd(self):
        argopt  = '-A "mixed_add@arg1/i32%rdi,fparg1/32%xmm0" '
        argopt += '-A "mixed_sub@arg1/x%rdi,arg2%rsi" '
        argopt += '-A "mixed_mul@fparg1%xmm0,arg1/i64" '
        argopt += '-A "mixed_div@arg1/i64,fparg1/80%stack+1" '
        argopt += '-A "mixed_str@arg1/s%rdi,fparg1%xmm0"'

        import platform
        if platform.machine().startswith('arm'):
            argopt = argopt.replace('%rdi', '%r0')
            argopt = argopt.replace('%rsi', '%r1')
            argopt = argopt.replace('32%xmm0', '32%s0')
            argopt = argopt.replace('%xmm0', '%d0')
            argopt = argopt.replace('fparg1/80%stack+1', 'fparg1/80')

        return '%s %s %s' % (TestBase.uftrace_cmd, argopt, 't-' + self.name)
