#!/usr/bin/env python3

import subprocess as sp

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'struct', """
uftrace_begin(ctx)
  record  : False
  version : v0.10-17-g8d1b ( x86_64 dwarf python luajit tui perf sched dynamic )
  cmds    : t-struct

11332966.196463691  50529: [entry] main(4006ef) depth: 0
11332966.196464540  50529: [entry] foo(40068f) depth: 1
  args[0] <class 'str'>: struct: Option{}
  args[1] <class 'str'>: struct: StringRef{}
  args[2] <class 'int'>: 44
  args[3] <class 'int'>: 55
  args[4] <class 'int'>: 66
11332966.196670289  50529: [exit ] foo(40068f) depth: 1
11332966.196671664  50529: [exit ] main(4006ef) depth: 0
  retval  <class 'int'>: 0

uftrace_end()
""", cflags='-g', sort='dump')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature or not 'python' in self.feature:
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
        self.option = '-S %s/scripts/dump.py -a --no-libcall --no-event --record' % self.basedir

    def fixup(self, cflags, result):
        # handle the difference between python2 and python3 output
        result = result.replace(" <class 'int'", " <type 'long'")
        return result.replace(" <class ", " <type ")
