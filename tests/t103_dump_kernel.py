#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp
import os

TDIR='xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', """
{"traceEvents":[
{"ts":14510734172,"ph":"B","pid":32687,"name":"main"},
{"ts":14510734172,"ph":"B","pid":32687,"name":"getpid"},
{"ts":14510734173,"ph":"E","pid":32687,"name":"getpid"},
{"ts":14510734176,"ph":"B","pid":32687,"name":"getppid"},
{"ts":14510734177,"ph":"B","pid":32687,"name":"sys_getppid"},
{"ts":14510734177,"ph":"E","pid":32687,"name":"sys_getppid"},
{"ts":14510734178,"ph":"E","pid":32687,"name":"getppid"},
{"ts":14510734178,"ph":"B","pid":32687,"name":"getpgid"},
{"ts":14510734179,"ph":"B","pid":32687,"name":"sys_getpgid"},
{"ts":14510734180,"ph":"E","pid":32687,"name":"sys_getpgid"},
{"ts":14510734180,"ph":"E","pid":32687,"name":"getpgid"},
{"ts":14510734180,"ph":"B","pid":32687,"name":"getsid"},
{"ts":14510734181,"ph":"B","pid":32687,"name":"sys_getsid"},
{"ts":14510734182,"ph":"E","pid":32687,"name":"sys_getsid"},
{"ts":14510734182,"ph":"E","pid":32687,"name":"getsid"},
{"ts":14510734182,"ph":"B","pid":32687,"name":"getuid"},
{"ts":14510734183,"ph":"B","pid":32687,"name":"sys_getuid"},
{"ts":14510734183,"ph":"E","pid":32687,"name":"sys_getuid"},
{"ts":14510734184,"ph":"E","pid":32687,"name":"getuid"},
{"ts":14510734184,"ph":"B","pid":32687,"name":"geteuid"},
{"ts":14510734184,"ph":"B","pid":32687,"name":"sys_geteuid"},
{"ts":14510734185,"ph":"E","pid":32687,"name":"sys_geteuid"},
{"ts":14510734185,"ph":"E","pid":32687,"name":"geteuid"},
{"ts":14510734185,"ph":"B","pid":32687,"name":"getgid"},
{"ts":14510734186,"ph":"B","pid":32687,"name":"sys_getgid"},
{"ts":14510734187,"ph":"E","pid":32687,"name":"sys_getgid"},
{"ts":14510734187,"ph":"E","pid":32687,"name":"getgid"},
{"ts":14510734187,"ph":"B","pid":32687,"name":"getegid"},
{"ts":14510734188,"ph":"B","pid":32687,"name":"sys_getegid"},
{"ts":14510734188,"ph":"E","pid":32687,"name":"sys_getegid"},
{"ts":14510734188,"ph":"E","pid":32687,"name":"getegid"},
{"ts":14510734189,"ph":"E","pid":32687,"name":"main"}
], "metadata": {
"command_line":"uftrace record -k -d xxx t-getids ",
"recorded_time":"Sun Oct  2 20:52:31 2016"
} }
""", sort='chrome')

    def pre(self):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        record_cmd = '%s record -k -N %s@kernel -d %s %s' % \
                     (TestBase.ftrace, 'smp_irq_work_interrupt', TDIR, 't-' + self.name)
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        return '%s dump -k --chrome -d %s' % (TestBase.ftrace, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret
