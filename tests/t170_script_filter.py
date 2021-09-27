#!/usr/bin/env python

import subprocess as sp

from runtest import TestBase

FILE='script.py'

script = """
UFTRACE_FUNCS = [ "a", "b" ]

def uftrace_entry(ctx):
  print("%s enter" % (ctx["name"]))

def uftrace_exit(ctx):
  print("%s exit" % (ctx["name"]))
"""

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
a enter
b enter
b exit
a exit
""")

    def prerun(self, timeout):
        script_cmd = '%s script' % (TestBase.uftrace_cmd)
        p = sp.Popen(script_cmd.split(), stdout=sp.PIPE, stderr=sp.PIPE)
        if p.communicate()[1].decode(errors='ignore').startswith('WARN:'):
            return TestBase.TEST_SKIP

        f = open(FILE, 'w')
        f.write(script)
        f.close()

        self.subcmd = 'record'
        self.option = ''
        self.exearg = 't-' + self.name

        record_cmd = self.runcmd()
        self.pr_debug("prerun command: " + record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'script'
        self.option = '-S ' + FILE
        self.exearg = ''

    def sort(self, output):
        return output.strip()
