#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', result="""
========== TASK GRAPH ==========
# TOTAL TIME   SELF TIME     TID     TASK NAME
   16.172 ms  356.762 us  [129306] : t-fork
                                   :  |    
   11.015 us   11.015 us  [129317] :  +----t-fork
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '--task'
        self.exearg = ''

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
