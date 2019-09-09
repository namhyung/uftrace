#!/usr/bin/env python

from runtest import TestBase
import subprocess as sp

TDIR = 'xxx'

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'fork', """
#         TIMESTAMP       FLAGS     TID    TASK              DATA SIZE
        347768.688479931  FS     [ 27364]  t-fork                0.000 MB
        347768.711664373  F      [ 27366]  t-fork                0.000 MB
""")

    def pre(self):
        record_cmd = '%s record -d %s %s' % (TestBase.uftrace_cmd, TDIR, 't-fork')
        sp.call(record_cmd.split())
        return TestBase.TEST_SUCCESS

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '--task'

        return '%s info %s -d %s' % (uftrace, options, TDIR)

    def post(self, ret):
        sp.call(['rm', '-rf', TDIR])
        return ret

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
