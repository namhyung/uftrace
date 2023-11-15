#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'hello', """
cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
number of cpus      : 12 / 12 (online / possible)
memory info         : 19.8 / 23.5 GB (free / total)
kernel version      : Linux 4.5.4-1-ARCH
hostname            : sejong
distro              : "Arch Linux"
perf_event_paranoid : 2
kptr_restrict       : 1
""")

    def setup(self):
        self.subcmd = 'info'
        self.option = '--system'
        self.exearg = ''

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#'):
                continue
            if ':' not in ln:
                continue
            label = ln.split(':', 1)[0].rstrip()
            result.append(label)
        return '\n'.join(result)
