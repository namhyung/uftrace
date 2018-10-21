#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
NOFILTERS='-N __monstartup -N __cxa_atexit'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'forkexec', result="""
# Function Call Graph for 't-abc' (session: 327202376e209585)
========== FUNCTION CALL GRAPH ==========
   5.824 us : (1) t-abc
   5.824 us : (1) main
   5.411 us : (1) a
   5.141 us : (1) b
   4.670 us : (1) c
   0.967 us : (1) getpid

# Function Call Graph for 't-forkexec' (session: f34056bd485963b3)
========== FUNCTION CALL GRAPH ==========
   3.679 ms : (1) t-forkexec
   3.679 ms : (1) main
 127.172 us :  +-(1) fork
            :  | 
   3.527 ms :  +-(1) waitpid
            :  | 
            :  +-(1) execl
""", sort='graph')

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'abc', cflags, ldflags)
        ret += TestBase.build(self, self.name, cflags, ldflags)
        return ret

    def pre(self):
        record_cmd = '%s record %s -d %s %s' % (TestBase.uftrace_cmd, NOFILTERS, TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s' % (TestBase.uftrace_cmd, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

    def fixup(self, cflags, result):
        return result.replace("readlink", """memset
            :  | 
   9.814 us :  +-(1) readlink""")
