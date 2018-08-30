#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR  = 'xxx'
TDIR2 = 'xxx/uftrace.data'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sleep', """
# DURATION    TID     FUNCTION
            [  395] | main() {
            [  395] |   foo() {
            [  395] |     mem_alloc() {
   1.328 us [  395] |       malloc();
   1.924 us [  395] |     } /* mem_alloc */
            [  395] |     bar() {
            [  395] |       usleep() {
   2.088 ms [  395] |         /* linux:schedule */
   2.105 ms [  395] |       } /* usleep */
   2.109 ms [  395] |     } /* bar */
            [  395] |     mem_free() {
   3.137 us [  395] |       free();
   3.783 us [  395] |     } /* mem_free */
   2.120 ms [  395] |   } /* foo */
   2.121 ms [  395] | } /* main */
""")

    recv_p = None

    def pre(self):
        if not TestBase.check_dependency(self, 'perf_context_switch'):
            return TestBase.TEST_SKIP
        if not TestBase.check_perf_paranoid(self):
            return TestBase.TEST_SKIP

        recv_cmd = '%s recv -d %s' % (TestBase.uftrace_cmd, TDIR)
        self.recv_p = sp.Popen(recv_cmd.split())

        options = '-H %s -E %s' % ('localhost', 'linux:schedule')
        record_cmd = '%s record %s %s' % (TestBase.uftrace_cmd, options, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s' % (TestBase.uftrace_cmd.split()[0], TDIR2)

    def post(self, ret):
        self.recv_p.terminate()
        sp.call(['rm', '-rf', TDIR])
        return ret
