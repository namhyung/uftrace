#!/usr/bin/env python3

import re

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION [SOURCE]
   0.234 us [ 19939] | __cxa_atexit();
            [ 19939] | main() {
            [ 19939] |   a() { /* from s-abc.c:N */
            [ 19939] |     b() { /* from s-abc.c:N */
            [ 19939] |       c() { /* from s-abc.c:N */
   1.120 us [ 19939] |         getpid();
   1.697 us [ 19939] |       } /* c */
   2.044 us [ 19939] |     } /* b */
   2.329 us [ 19939] |   } /* a */
   2.644 us [ 19939] | } /* main */
""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = "-T '^.$@callsite'"

    def runcmd(self):
        # callsite events must not be filtered out by the default --no-event
        return TestBase.runcmd(self).replace('--no-event', '')

    def sort(self, output):
        """ Replace exact line numbers with N to ignore compiler-dependent
            shifts, and strip directory prefix from paths so the test is
            stable across optimization levels and build environments. """
        result = []
        before_main = True
        for ln in output.split('\n'):
            if ln.find(' | main()') > 0:
                before_main = False
            if before_main:
                continue
            if ln.strip() == '':
                break

            rest = ln.split('|', 1)[-1]
            # strip directory prefix from filenames and normalize line numbers
            rest = re.sub(r'/[\w./-]+/(\S+\.c):\d+', r'\1:N', rest)
            result.append(rest.rstrip())

        return '\n'.join(result)
