#!/usr/bin/env python3

import subprocess as sp

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'struct', """
uftrace_begin(ctx)
  record  : false
  version : v0.10-17-g8d1b ( x86_64 dwarf python luajit tui perf sched dynamic )
  cmds    : t-struct

514662126420.5094  29459: [entry] main(40067f) depth: 0
514662126420.5754  29459: [entry] foo(40061f) depth: 1
  args[1] string: struct: Option{}
  args[2] string: struct: StringRef{}
  args[3] number: 44
  args[4] number: 55
  args[5] number: 66
514662126427.20138  29459: [exit ] foo(40061f) depth: 1
514662126427.21036  29459: [exit ] main(40067f) depth: 0
  retval  number: 0

uftrace_end()
""", cflags='-g', sort='dump')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature or not 'luajit' in self.feature:
            return TestBase.TEST_SKIP
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def prerun(self, timeout):
        script_cmd = '%s script' % (TestBase.uftrace_cmd)
        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'script'
        self.option = '-S %s/scripts/dump.lua -a --no-libcall --no-event --record' % self.basedir
