#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', result="""
# Function Call Graph for 'main' (session: de27777d0a966d5a)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  13.120 ms
   [0] main (0x56366ebab7fc)

========== FUNCTION CALL GRAPH ==========
# TOTAL TIME   FUNCTION [SOURCE]
   13.120 ms : (1) main
  694.492 us :  +-(2) foo [/home/eslee/soft/uftrace/tests/s-sort.c:10]
  688.800 us :  | (6) loop [/home/eslee/soft/uftrace/tests/s-sort.c:3]
             :  | 
   10.748 ms :  +-(1) bar [/home/eslee/soft/uftrace/tests/s-sort.c:17]
   10.183 ms :    (1) usleep
""", sort='graph', cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def prepare(self):
        self.subcmd = 'record'
        self.option = '--srcline'
        self.exearg = 't-' + self.name
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.option = '--srcline'
        self.exearg = 'main'

    def sort(self, output):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        mode = 0
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#'):
                continue
            # A graph result consists of backtrace and calling functions
            if ln.startswith('=============== BACKTRACE ==============='):
                mode = 1
                continue
            if ln.startswith('========== FUNCTION CALL GRAPH =========='):
                mode = 2
                continue
            if mode == 1:
                if ln.startswith(' backtrace #'):
                    result.append(ln.split(',')[0])  # remove time part
                if ln.startswith('   ['):
                    result.append(ln.split('(')[0])  # remove '(addr)' part
            if mode == 2:
                if " : " in ln:
                    func = ln.split(':', 1)[1].split('[')  # remove time part
                    if len(func) < 2 :
                        result.append('%s' % (func[-1]))
                    else :
                        # extract basename and line number of source location
                        result.append('%s %s' % (func[-2], func[-1][0:-1].split('/')[-1]))
                else:
                    result.append(ln)

        return '\n'.join(result)
