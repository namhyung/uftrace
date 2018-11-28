#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR  = 'xxx'
TDIR2 = 'xxx/uftrace.data'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sdt', """
# DURATION    TID     FUNCTION
   9.392 us [28141] | __monstartup();
  12.912 us [28141] | __cxa_atexit();
            [28141] | main() {
            [28141] |   foo() {
            [28141] |     /* uftrace:event */
   2.896 us [28141] |   } /* foo */
   3.017 us [28141] | } /* main */
""")
        self.gen_port()

    recv_p = None

    def pre(self):
        recv_cmd = '%s recv -d %s --port %s' % (TestBase.uftrace_cmd, TDIR, self.port)
        self.recv_p = sp.Popen(recv_cmd.split())

        server = '-H 127.0.0.1'
        port   = '--port %s' % self.port
        option = '-E uftrace:event'
        prog   = 't-' + self.name
        record_cmd = '%s record %s %s %s %s' % (TestBase.uftrace_cmd, server, port, option, prog)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s replay -d %s' % (TestBase.uftrace_cmd.split()[0], TDIR2)

    def post(self, ret):
        self.recv_p.terminate()
        sp.call(['rm', '-rf', TDIR])
        return ret
