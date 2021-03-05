#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR = 'xxx'
TMPF = 'out'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION    TID     FUNCTION
  62.202 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   a() {
            [28141] |     b() {
            [28141] |       c() {
   0.753 us [28141] |         getpid();
   1.430 us [28141] |       } /* c */
   1.915 us [28141] |     } /* b */
   2.405 us [28141] |   } /* a */
   3.005 us [28141] | } /* main */
""")

    def prerun(self, timeout):
        self.gen_port()
        self.file_p = open(TMPF, 'w+')

        recv_cmd  = [TestBase.uftrace_cmd, 'recv']
        recv_cmd += TestBase.default_opt.split()
        recv_cmd += ['-d', TDIR, '--port', str(self.port)]
        recv_cmd += ['--run-cmd', '%s %s' % (TestBase.uftrace_cmd, 'replay')]
        self.pr_debug('prerun command: ' + ' '.join(recv_cmd))
        self.recv_p = sp.Popen(recv_cmd, stdout=self.file_p, stderr=self.file_p)

        record_cmd  = [TestBase.uftrace_cmd, 'record']
        record_cmd += TestBase.default_opt.split()
        record_cmd += ['--host', 'localhost', '--port', str(self.port)]
        record_cmd += ['t-' + self.name]
        self.pr_debug('prerun command: ' + ' '.join(record_cmd))
        sp.call(record_cmd)

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        # run replay at recv time and print the result now
        return 'cat ' + TMPF

    def postrun(self, ret):
        self.recv_p.terminate()
        self.file_p.close()
        return ret
