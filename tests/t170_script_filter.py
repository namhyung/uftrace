#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
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

    def pre(self):
        f = open(FILE, 'w')
        f.write(script)
        f.close()

        uftrace = TestBase.uftrace_cmd
        program = 't-' + self.name
        record_cmd = '%s record -d %s %s' % (uftrace, TDIR, program)

        self.pr_debug("record command: %s" % record_cmd)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '-S ' + FILE
        return '%s script -d %s %s' % (uftrace, TDIR, options)

    def sort(self, output):
        return output.strip()

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR, FILE])
        return ret
