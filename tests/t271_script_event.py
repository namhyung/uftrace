#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase

FILE='script.py'

script = """
def uftrace_entry(ctx):
  pass
def uftrace_exit(ctx):
  pass
def uftrace_event(ctx):
  args = ''
  if "args" in ctx:
    for kv in ctx["args"].split(" "):
      args += ' ' + kv.split("=")[0]
  print(ctx["name"] + args)
"""

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
read:proc/statm vmsize vmrss shared
diff:proc/statm vmsize vmrss shared
""")

    def runcmd(self):
        return TestBase.runcmd(self).replace('--no-event', '')

    def prerun(self, timeout):
        script_cmd = '%s script' % (TestBase.uftrace_cmd)
        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP

        f = open(FILE, 'w')
        f.write(script)
        f.close()

        self.subcmd = 'record'
        self.option = '-T a@read=proc/statm --no-sched'

        record_cmd = self.runcmd()

        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split(), stdout=sp.PIPE)
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'script'
        self.option = '-S ' + FILE

    def sort(self, output):
        return output.strip()
