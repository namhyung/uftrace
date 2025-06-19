#!/usr/bin/env python3

import select
import subprocess as sp
import time

from runtest import TestBase

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
        self.recv_p = sp.Popen(recv_cmd, stdout=sp.PIPE, stderr=sp.PIPE)

        time.sleep(0.1)

        epolls = select.epoll()
        epolls.register(self.recv_p.stdout, select.EPOLLIN)

        record_cmd  = [TestBase.uftrace_cmd, 'record']
        record_cmd += TestBase.default_opt.split()
        record_cmd += ['--host', 'localhost', '--port', str(self.port)]
        if self.p_flag:
            record_cmd += self.p_flag.split()
        record_cmd += ['t-' + self.name]
        self.pr_debug('prerun command: ' + ' '.join(record_cmd))
        sp.call(record_cmd, stderr=sp.PIPE)

        epolls.poll(timeout=timeout)

        self.recv_p.terminate()

        out = self.recv_p.communicate()[0].decode(errors='ignore')
        self.file_p.write(out)
        self.file_p.flush()
        self.file_p.close()
        epolls.close()

        return TestBase.TEST_SUCCESS

    def runcmd(self):
        # run replay at recv time and print the result now
        return 'cat ' + TMPF

    def postrun(self, ret):
        return ret
