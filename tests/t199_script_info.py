#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
False
v0.8.3-10/gfbfac3
('foo', 'bar')
""")

    def prerun(self, timeout):
        self.subcmd = 'script'
        self.option = ''
        self.exearg = ''

        script_cmd = self.runcmd()
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
        self.option = '-F main -S %s/scripts/info.py' % self.basedir
        self.exearg = 'foo bar'

    def sort(self, output):
        result = output.strip().split('\n')
        result[1] = 'uftrace version'  # overwrite the version number
        return '\n'.join(result)
