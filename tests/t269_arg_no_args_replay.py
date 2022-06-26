#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exp-str', result="""
# DURATION     TID     FUNCTION
   1.700 us [114150] | __monstartup();
   0.980 us [114150] | __cxa_atexit();
            [114150] | main() {
 311.089 us [114150] |   str_cpy();
   0.734 us [114150] |   str_cpy();
   0.597 us [114150] |   str_cat();
   0.537 us [114150] |   str_cpy();
   0.454 us [114150] |   str_cat();
 317.939 us [114150] | } /* main */
""")

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
        return '%s replay -d %s --no-args' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
