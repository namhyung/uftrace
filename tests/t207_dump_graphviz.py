#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """digraph "%s" {

        # Attributes
        splines=ortho;
        concentrate=true;
        node [shape="rect",fontsize="7",style="filled"];
        edge [fontsize="7"];

        # Elements
        "main" [xlabel = "Calls : 1"]
        "main" -> "a" [xlabel = "Calls : 1"]
        "a" -> "b" [xlabel = "Calls : 1"]
        "b" -> "c" [xlabel = "Calls : 1"]
        }
        """)
        self.result = self.result % os.path.join(self.test_dir, "t-abc")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump -d %s -F main -D 4 --graphviz' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output):
        """ This function post-processes output of the test to be compared .
            It ignores blank and comment (#) lines and remaining functions.  """
        result = []
        for line, ln in enumerate(output.split('\n')):
            # remove all comments
            ln = ln.strip()
            if ln.startswith('#'):
                continue
            result.append(ln)
        return '\n'.join(result)
