#!/usr/bin/env python3

import os
import subprocess as sp

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'getids', serial=True, result="""
{"traceEvents":[
{"ts":14510734170,"ph":"M","pid":32687,"name":"process_name","args":{"name": "[32687] t-getids"}},
{"ts":14510734170,"ph":"M","pid":32687,"name":"thread_name","args":{"name": "[32687] t-getids"}},
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

    def prerun(self, timeout):
        if os.geteuid() != 0:
            return TestBase.TEST_SKIP
        if os.path.exists('/.dockerenv'):
            return TestBase.TEST_SKIP

        self.subcmd = 'record'
        self.option = '-k -F main'
        record_cmd = self.runcmd()
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'dump'
        self.option = '-k --chrome'

    def fixup(self, cflags, result):
        result = result.replace("""\
{"ts":14510734172,"ph":"B","pid":32687,"name":"getpid"},
{"ts":14510734173,"ph":"E","pid":32687,"name":"getpid"},\
""",
"""\
{"ts":14510734172,"ph":"B","pid":32687,"name":"getpid"},
{"ts":14510734172,"ph":"B","pid":32687,"name":"sys_getpid"},
{"ts":14510734172,"ph":"E","pid":32687,"name":"sys_getpid"},
{"ts":14510734173,"ph":"E","pid":32687,"name":"getpid"},\
""")
        uname = os.uname()

        # Later version changed syscall routines
        major, minor, release = uname[2].split('.', 2)
        if uname[0] == 'Linux' and uname[4] == 'x86_64':
            if int(major) == 6 and int(minor) >= 9:
                import re
                result = re.sub(r'sys_get[a-z]*', 'x64_sys_call', result)
            elif int(major) >= 5 or (int(major) == 4 and int(minor) >= 17):
                result = result.replace('sys_get', '__x64_sys_get')
        if uname[0] == 'Linux' and uname[4] == 'aarch64' and \
           int(major) >= 5 or (int(major) == 4 and int(minor) >= 19):
            result = result.replace('sys_get', '__arm64_sys_get')

        return result
