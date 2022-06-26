#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-str', result="""
uftrace file header: magic         = 4674726163652100
uftrace file header: version       = 4
uftrace file header: header size   = 40
uftrace file header: endian        = 1 (little)
uftrace file header: class         = 2 (64 bit)
uftrace file header: features      = 0x77b (PLTHOOK | TASK_SESSION | ARGUMENT | RETVAL | SYM_REL_ADDR | MAX_STACK | PERF_EVENT | AUTO_ARGS | DEBUG_INFO)
uftrace file header: info          = 0x3fff

reading 72944.dat
108370.324774953  72944: [entry] __monstartup(aaaacc4c0750) depth: 0
108370.324775495  72944: [exit ] __monstartup(aaaacc4c0750) depth: 0
108370.324776370  72944: [entry] __cxa_atexit(aaaacc4c0720) depth: 0
108370.324776453  72944: [exit ] __cxa_atexit(aaaacc4c0720) depth: 0
108370.324777203  72944: [entry] main(aaaacc4c0a08) depth: 0
108370.324777286  72944: [entry] str_cpy(aaaacc4c09a4) depth: 1
108370.324850202  72944: [exit ] str_cpy(aaaacc4c09a4) depth: 1
108370.324850910  72944: [entry] str_cpy(aaaacc4c09a4) depth: 1
108370.324851243  72944: [exit ] str_cpy(aaaacc4c09a4) depth: 1
108370.324851493  72944: [entry] str_cat(aaaacc4c0918) depth: 1
108370.324851785  72944: [exit ] str_cat(aaaacc4c0918) depth: 1
108370.324851993  72944: [entry] str_cpy(aaaacc4c09a4) depth: 1
108370.324852243  72944: [exit ] str_cpy(aaaacc4c09a4) depth: 1
108370.324852410  72944: [entry] str_cat(aaaacc4c0918) depth: 1
108370.324852660  72944: [exit ] str_cat(aaaacc4c0918) depth: 1
108370.324852827  72944: [exit ] main(aaaacc4c0a08) depth: 0
""", sort='dump')

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def prerun(self, timeout):
        record_cmd = '%s record -d %s -A ^str_@arg1/s,arg2/s -R ^str_@retval/s %s %s' \
                        % (TestBase.uftrace_cmd, TDIR, TestBase.default_opt, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump -d %s --no-args' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
