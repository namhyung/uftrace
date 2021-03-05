#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'forkexec', result="""
# Function Call Graph for 'main' (session: 327202376e209585)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   5.824 us
   [0] main (0x400530)

========== FUNCTION CALL GRAPH ==========
   5.824 us : (1) main
   5.411 us : (1) a
   5.141 us : (1) b
   4.670 us : (1) c
   0.967 us : (1) getpid

# Function Call Graph for 'main' (session: f34056bd485963b3)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time   3.679 ms
   [0] main (0x4005b0)

========== FUNCTION CALL GRAPH ==========
   3.679 ms : (1) main
 127.172 us :  +-(1) fork
            :  | 
   3.527 ms :  +-(1) waitpid
""")

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'abc', cflags, ldflags)
        ret += TestBase.build(self, self.name, cflags, ldflags)
        return ret

    def prepare(self):
        self.subcmd = 'record'
        self.exearg = 't-' + self.name
        return self.runcmd()

    def setup(self):
        self.subcmd = 'graph'
        self.exearg = 'main'

    def fixup(self, cflags, result):
        return result.replace("readlink", """memset
            :  | 
   9.814 us :  +-(1) readlink""")

    def sort(self, output):
        """ This function post-processes output of the test to be compared.
            It ignores blank and comment (#) lines and header lines.  """
        result = []
        mode = 0
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#'):
                continue
            if ln.startswith('=============== BACKTRACE ==============='):
                mode = 1  # it seems to be broken in this case
                continue
            if ln.startswith('========== FUNCTION CALL GRAPH =========='):
                mode = 2
                continue
            if mode == 1:
                pass      # compare function graph part only
            if mode == 2:
                result.append(ln.split(':')[1])      # remove time part

        return '\n'.join(result)
