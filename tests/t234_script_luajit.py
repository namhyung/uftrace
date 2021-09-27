#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', '5')

    def prerun(self, timeout):
        self.subcmd = 'script'
        self.option = '-S %s/scripts/count.lua --record' % self.basedir
        script_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + script_cmd)

        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.option = '-F main -S %s/scripts/count.lua' % self.basedir

    def sort(self, output):
        return output.strip()
