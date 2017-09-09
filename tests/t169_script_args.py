#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FILE='script.py'

script = """
def uftrace_entry(ctx):
  if "args" in ctx:
    print("%s(%s)" % (ctx["name"], ctx["args"][0]))

def uftrace_exit(ctx):
  pass
"""

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'openclose', 'fopen(/dev/null)')

    def pre(self):
        f = open(FILE, 'w')
        f.write(script)
        f.close()

        uftrace = TestBase.ftrace
        options = '-A fopen@arg1/s'
        program = 't-' + self.name
        record_cmd = '%s record -d %s %s %s' % (uftrace, TDIR, options, program)

        self.pr_debug("record command: %s" % record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.ftrace
        options = '-S ' + FILE
        return '%s script -d %s %s' % (uftrace, TDIR, options)

    def sort(self, output):
        return output.strip()

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR, FILE])
        return ret
