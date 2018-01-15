#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR='xxx'
FUNC='main'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# Function Call Graph for 'main' (session: b508f628ffe7287f)
=============== BACKTRACE ===============
 backtrace #0: hit 1, time  17.931 us
   [0] main (0x400790)

========== FUNCTION CALL GRAPH ==========
  17.931 us : (1) main
   2.087 us :  +-(2) operator new
            :  | 
   0.183 us :  +-(1) ns::ns1::foo::foo
            :  | 
   4.816 us :  +-(1) ns::ns1::foo::bar
   2.810 us :  |  +-(1) ns::ns1::foo::bar1
   2.536 us :  |  | (1) ns::ns1::foo::bar2
   2.240 us :  |  | (1) ns::ns1::foo::bar3
            :  |  | 
   1.356 us :  |  +-(1) free
            :  | 
   2.624 us :  +-(2) operator delete
            :  | 
   0.093 us :  +-(1) ns::ns2::foo::foo
            :  | 
   1.997 us :  +-(1) ns::ns2::foo::bar
   1.286 us :     +-(1) ns::ns2::foo::bar1
   1.017 us :     | (1) ns::ns2::foo::bar2
   0.740 us :     | (1) ns::ns2::foo::bar3
            :     | 
   0.187 us :     +-(1) free
""", sort='graph')

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-namespace')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s graph -d %s -D5 %s' % (TestBase.uftrace_cmd, TDIR, FUNC)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
