#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'struct', """
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x67a (TASK_SESSION | ARGUMENT | RETVAL | SYM_REL_ADDR | MAX_STACK | AUTO_ARGS | DEBUG_INFO)
uftrace file header: info          = 0x3fff

reading 3121.dat
11431966.432931623   3121: [entry] main(400673) depth: 0
11431966.432932393   3121: [entry] foo(40061f) depth: 1
11431966.432932393   3121: [args ] length = 36
  args[0] struct Option:
        0b 16 00 00 00 00 00 00  00 00 00
  args[1] struct StringRef:
  args[2] d64: 0x000000000000002c
  args[3] d64: 0x0000000000000037
  args[4] d64: 0x0000000000000042
11431966.433134239   3121: [exit ] foo(40061f) depth: 1
11431966.433135754   3121: [exit ] main(400673) depth: 0
11431966.433135754   3121: [retval] length = 8
  retval d64: 0x0000000000000000
""", cflags='-g', sort='dump')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        self.option = '-a --no-libcall'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'

    def fixup(self, cflags, result):
        # 32-bit will show the output differently
        return result.replace('d64: 0x00000000', 'd32: 0x')
