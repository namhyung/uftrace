#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
#         TIMESTAMP       FLAGS     TID    TASK              DATA SIZE
        347768.688479931  FS     [ 27364]  t-fork                0.000 MB
        347768.711664373  F      [ 27366]  t-fork                0.000 MB
""")

    def prepare(self):
        self.subcmd = 'record'
        return self.runcmd()

    def setup(self):
        self.subcmd = 'info'
        self.option = '--task'

    def sort(self, output):
        import re
        result = []

        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue

            # ignore time part
            ln = ln[24:]

            # replace tid part into common string
            task = re.sub(r'\[ *[0-9]+\]', '[TID]', ln)
            result.append(task)

        return '\n'.join(result)
