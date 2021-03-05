#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'hello', """
# system information
# ==================
# program version     : uftrace v0.8.1-133-g7f71
# recorded on         : Mon Nov 27 09:40:31 2017
# cmdline             : ../uftrace record --no-pager --no-event -L.. t-hello \\"uftrace\\"
# cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
# number of cpus      : 12 / 12 (online / possible)
# memory info         : 13.2 / 23.5 GB (free / total)
# system load         : 3.25 / 3.17 / 3.11 (1 / 5 / 15 min)
# kernel version      : Linux 4.13.11-1-ARCH
# hostname            : sejong
# distro              : "Arch Linux"
#
# process information
# ===================
# number of tasks     : 1
# task list           : 10217
# exe image           : /home/namhyung/project/uftrace/tests/t-hello
# build id            : 7fde527c74f398c5f48b5ec30173d2c17366dd90
# exit status         : exited with code: 0
# elapsed time        : 0.004278080 sec
# cpu time            : 0.002 / 0.002 sec (sys / user)
# context switch      : 1 / 0 (voluntary / involuntary)
# max rss             : 3284 KB
# page fault          : 0 / 197 (major / minor)
# disk iops           : 0 / 16 (read / write)""")


    def prerun(self, timeout):
        self.subcmd  = 'record'
        self.exearg += ' "uftrace"'
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)

        f = open('/dev/null')
        sp.call(record_cmd.split(), stdout=f, stderr=f)
        f.close()
        return TestBase.TEST_SUCCESS

    def setup(self):
        self.subcmd = 'info'
        self.exearg = ''

    def sort(self, output):
        for ln in output.split('\n'):
            if ln.startswith('# cmdline'):
                return ln.split()[-1]
        return ''
