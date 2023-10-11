#!/usr/bin/env python3

import subprocess as sp

from runtest import TestBase

def get_func_size(elfbin, funcname):
    # expected output
    # $ readelf -s t-unroll | grep small
    #     28: 0000000000001185    30 FUNC    GLOBAL DEFAULT   15 small
    cmd1 = "readelf -s %s" % elfbin
    cmd2 = "grep %s" % funcname

    size = 0
    with sp.Popen(cmd1.split(), stdout=sp.PIPE) as p1:
        with sp.Popen(cmd2.split(), stdin=p1.stdout, stdout=sp.PIPE) as p2:
            line = p2.communicate()[0].decode(errors='ignore')
            size = int(line.split()[2])
    return size

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'unroll', """
# DURATION    TID     FUNCTION
            [ 72208] | main() {
   0.252 us [ 72208] |   big();
   1.802 us [ 72208] | } /* main */

""")

    def prerun(self, timeout):
        if not TestBase.check_arch_full_dynamic_support(self):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def build(self, name, cflags='', ldflags=''):
        cflags = self.strip_tracing_flags(cflags)
        cflags += ' -funroll-loops'
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        size = get_func_size('t-' + self.name, 'small')
        self.option = '-P. -Z %d' % (size + 1)
