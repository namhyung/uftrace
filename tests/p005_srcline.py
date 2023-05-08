#!/usr/bin/env python

import re

from runtest import PyTestBase

class TestCase(PyTestBase):
    def __init__(self):
        PyTestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
            [ 28141] | __main__.<module>() { /* /home/namhyung/project/uftrace/tests/s-abc.py:1 */
            [ 28141] |   a() { /* /home/namhyung/project/uftrace/tests/s-abc.py:4 */
            [ 28141] |     b() { /* /home/namhyung/project/uftrace/tests/s-abc.py:7 */
            [ 28141] |       c() { /* /home/namhyung/project/uftrace/tests/s-abc.py:10 */
   0.753 us [ 28141] |         posix.getpid();
   1.430 us [ 28141] |       } /* c */
   1.915 us [ 28141] |     } /* b */
   2.405 us [ 28141] |   } /* a */
   3.005 us [ 28141] | } /* __main__.<module> */
""")

    def setup(self):
        self.option = '--srcline'

    def sort(self, output, ignored=True):
        result = []
        for ln in output.split('\n'):
            # ignore blank lines and comments
            if ln.strip() == '' or ln.startswith('#'):
                continue
            line = ln.split('|', 1)[-1]
            # remove directory path and check the basename only
            func = re.sub(r'{ .*/s-abc.py:', '{ /* s-abc.py:', line)
            result.append(func)

        return '\n'.join(result)
