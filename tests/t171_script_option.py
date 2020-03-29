#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

FILE='script.py'

script = """
# uftrace-option: -A fopen@arg1/s

def uftrace_entry(ctx):
  if "args" in ctx:
    print("%s(%s)" % (ctx["name"], ctx["args"][0]))

def uftrace_exit(ctx):
  pass
"""

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', 'fopen(/dev/null)')

    def prerun(self, timeout):
        script_cmd = '%s script' % (TestBase.uftrace_cmd)
        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP

        f = open(FILE, 'w')
        f.write(script)
        f.close()
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'script'
        self.option = '-S %s --record' % FILE

    def sort(self, output):
        i = 0
        # skip warning for '-finstrument-functions'
        if output.startswith('uftrace: -A or -R might not work'):
            i = 1
        return output.strip().split('\n')[i]
