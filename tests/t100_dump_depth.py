#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x363 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK | PERF_EVENT | AUTO_ARGS)
uftrace file header: info          = 0x1bff

reading 5231.dat
58348.873444506   5231: [entry] main(400512) depth: 0
58348.873444843   5231: [entry] a(4006b2) depth: 1
58348.873445107   5231: [entry] b(4006a0) depth: 2
58348.873448707   5231: [exit ] b(4006a0) depth: 2
58348.873448996   5231: [exit ] a(4006b2) depth: 1
58348.873449309   5231: [exit ] main(400512) depth: 0
""", sort='dump')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump -d %s -F main -D 3' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def fixup(self, cflags, result):
        import platform

        if platform.architecture()[0] == '32bit':
            result = result.replace("2 (64 bit)", "1 (32 bit)")
        p = sp.Popen(['file', 't-' + self.name], stdout=sp.PIPE)
        if 'BuildID' not in p.communicate()[0].decode(errors='ignore'):
            result = result.replace("0xbff", "0xbfd")
        return result
