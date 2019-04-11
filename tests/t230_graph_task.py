#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import re

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', result="""
========== TASK GRAPH ==========
# TOTAL-TIME   SELF-TIME : TASK
  889.724 us  207.791 us : [27364] t-fork
                         :  |    
   11.706 us   11.706 us :  +----[27366] t-fork
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph --task -d %s %s' % (TestBase.uftrace_cmd, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def sort(self, output, ignored=False):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#'):
                continue
            # A graph result consists of backtrace and calling functions
            if ln.startswith('========== TASK GRAPH =========='):
                continue

            if " : " in ln:
                line = ln.split(':')[1]  # remove time part
                line = re.sub('\[\d+\]', 'TID', line)
                result.append(line)
            else:
                result.append(ln)

        return '\n'.join(result)
