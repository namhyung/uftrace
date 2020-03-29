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

    def setup(self):
        self.option = '-F main -f none'

    def sort(self, output, ignore_children=False):
        return output
