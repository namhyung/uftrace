#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x363 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK | PERF_EVENT | AUTO_ARGS)
uftrace file header: info          = 0x3bff

reading 5231.dat
58348.873444506   5231: [entry] main(400512) depth: 0
58348.873444843   5231: [entry] a(4006b2) depth: 1
58348.873445107   5231: [entry] b(4006a0) depth: 2
58348.873448707   5231: [exit ] b(4006a0) depth: 2
58348.873448996   5231: [exit ] a(4006b2) depth: 1
58348.873449309   5231: [exit ] main(400512) depth: 0
""", sort='dump')

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-F main -N c'

    def fixup(self, cflags, result):
        if TestBase.is_32bit(self):
            result = result.replace("2 (64 bit)", "1 (32 bit)")
        p = sp.Popen(['file', 't-' + self.name], stdout=sp.PIPE)
        if 'BuildID' not in p.communicate()[0].decode(errors='ignore'):
            result = result.replace("0xbff", "0xbfd")
        return result
