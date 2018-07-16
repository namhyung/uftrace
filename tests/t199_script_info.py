#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
False
v0.8.3-10/gfbfac3
('foo', 'bar')
""")

    def pre(self):
        script_cmd = '%s script' % (TestBase.uftrace_cmd)
        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP

        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-abc')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '-F main -S ../scripts/info.py foo bar'
        return '%s script -d %s %s' % (uftrace, TDIR, options)

    def sort(self, output):
        result = output.strip().split('\n')
        result[1] = 'uftrace version'  # overwrite the version number
        return '\n'.join(result)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
