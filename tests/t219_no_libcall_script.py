#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
uftrace_begin(ctx)
  record  : False
  version : v0.9.1-161-g13755 ( dwarf python tui perf sched )
  cmds    :

50895.869952000  73755: [entry] main(400787) depth: 0
50895.869952297  73755: [entry] foo(40071f) depth: 1
50895.869952533  73755: [exit ] foo(40071f) depth: 1
50895.869966333  73755: [entry] sighandler(400750) depth: 1
50895.869966473  73755: [entry] bar(400734) depth: 2
50895.869966617  73755: [exit ] bar(400734) depth: 2
50895.869967067  73755: [exit ] sighandler(400750) depth: 1
50895.869969790  73755: [entry] foo(40071f) depth: 1
50895.869969907  73755: [exit ] foo(40071f) depth: 1
50895.869970227  73755: [exit ] main(400787) depth: 0

uftrace_end()
""", sort='dump')

    def prerun(self, timeout):
        self.subcmd = 'script'
        self.option = ''
        self.exearg = ''

        script_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + script_cmd)
        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.exearg = 't-' + self.name
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'script'
        self.option = '-S %s/scripts/dump.py --no-libcall' % self.basedir
        self.exearg = ''
