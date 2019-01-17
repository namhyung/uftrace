#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x363 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK | PERF_EVENT | AUTO_ARGS)
uftrace file header: info          = 0x3bff

reading 73755.dat
50895.869952000  73755: [entry] main(400787) depth: 0
50895.869952297  73755: [entry] foo(40071f) depth: 1
50895.869952533  73755: [exit ] foo(40071f) depth: 1
50895.869966333  73755: [entry] sighandler(400750) depth: 2
50895.869966473  73755: [entry] bar(400734) depth: 3
50895.869966617  73755: [exit ] bar(400734) depth: 3
50895.869967067  73755: [exit ] sighandler(400750) depth: 2
50895.869969790  73755: [entry] foo(40071f) depth: 1
50895.869969907  73755: [exit ] foo(40071f) depth: 1
50895.869970227  73755: [exit ] main(400787) depth: 0
""", sort='dump')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump --no-libcall -d %s' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
