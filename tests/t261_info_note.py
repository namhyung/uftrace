#!/usr/bin/env python3

import subprocess as sp

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'hello', """
# system information
# ==================
# program version     : v0.10-52-gca6c ( x86_64 dwarf python luajit tui perf sched dynamic )
# recorded on         : Mon Aug 16 07:05:58 2021
# cmdline             : uftrace record t-hello note.txt
# cpu info            : ARM64 (v8)
# number of cpus      : 2 / 2 (online / possible)
# memory info         : 0.1 / 1.8 GB (free / total)
# system load         : 1.21 / 1.12 / 1.13 (1 / 5 / 15 min)
# kernel version      : Linux 5.10.21-200.fc33.aarch64
# hostname            : fedora
# distro              : "Fedora 33 (Workstation Edition)
#
# process information
# ===================
# number of tasks     : 1
# task list           : 19331(t-hello)
# exe image           : /home/honggyu/work/uftrace/tests/t-hello
# build id            : bbe710345ed7b36f7c83085837cbf24b1fba00fb
# pattern             : regex
# exit status         : exited with code: 0
# elapsed time        : 0.008521454 sec
# cpu time            : 0.007 / 0.001 sec (sys / user)
# context switch      : 2 / 1 (voluntary / involuntary)
# max rss             : 4844 KB
# page fault          : 0 / 349 (major / minor)
# disk iops           : 0 / 8 (read / write)
#
# extra note information
# ======================
You can leave a note for the recorded data.""")

    def prerun(self, timeout):
        self.subcmd  = 'record'
        self.exearg += ' note.txt'
        record_cmd = self.runcmd()
        self.pr_debug('prerun command: ' + record_cmd)

        f = open('/dev/null')
        sp.call(record_cmd.split(), stdout=f, stderr=f)
        f.close()
        return TestBase.TEST_SUCCESS

    def setup(self):
        with open('uftrace.data/note.txt', 'w+') as f:
            f.write('You can leave a note for the recorded data.')
        self.subcmd = 'info'
        self.exearg = ''

    def sort(self, output):
        header_match = 0
        for ln in output.split('\n'):
            if header_match == 0:
                if ln.startswith('# extra note information'):
                    header_match = 1
            elif header_match == 1:
                header_match = 2
            elif header_match == 2:
                return ln
        return ''
