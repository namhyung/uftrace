#!/usr/bin/env python3

from runtest import TestBase


class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'sort', """
#Total time,Self time,Calls,Function
10184916,73343,1,main
10081112,24541,1,bar
10056571,10056571,1,usleep
30461,1020,2,foo
29441,29441,6,loop
""")

    def prepare(self):
        self.subcmd = 'record'
        self.option = '-F main'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'report'
        self.option = '--format=csv'

    def sort(self, output):
        result = []

        for ln in output.split('\n'):
            if ln.strip() == '' or ln.startswith('#'):
                continue

            if ln.count(',') != 3:
                return 'invalid csv field count'

            line = [item.strip() for item in ln.split(',')]
            result.append('%s %s' % (line[2], line[3]))

        return '\n'.join(result)
