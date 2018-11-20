#!/usr/bin/env python

from runtest import TestBase
import re

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'chcpu', result="""
# DURATION     TID     FUNCTION
            [ 19611] | main() {
            [ 19611] |   /* watch:cpu (cpu=6) */
  32.050 us [ 19611] |   sysconf();
   1.105 us [ 19611] |   sched_getcpu();
            [ 19611] |   sched_setaffinity() {
  28.284 us [ 19611] |     /* linux:schedule */
            [ 19611] |     /* watch:cpu (cpu=0) */
  56.223 us [ 19611] |   } /* sched_setaffinity */
            [ 19611] |   sched_setaffinity() {
  16.719 us [ 19611] |     /* linux:schedule */
            [ 19611] |     /* watch:cpu (cpu=6) */
  37.281 us [ 19611] |   } /* sched_setaffinity */
 142.912 us [ 19611] | } /* main */
""")

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '-F main -W cpu -E "linux:*"'
        program = 't-' + self.name
        return '%s %s %s' % (uftrace, options, program)

    def sort(self, output):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            func = re.sub(r'cpu=[0-9a-f]+', 'cpu=N', line)
            result.append(func)

        return '\n'.join(result)
