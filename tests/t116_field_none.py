#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc',
"""main() {
  a() {
    b() {
      c() {
        getpid();
      } /* c */
    } /* b */
  } /* a */
} /* main */
""")

    def runcmd(self):
        return '%s -F main -f none %s' % (TestBase.uftrace_cmd, 't-' + self.name)

    def sort(self, output, ignore_children=False):
        return output
