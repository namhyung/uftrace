#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'thread-exec', """
# DURATION    TID     FUNCTION
            [23290] | main() {
  29.452 us [23290] |   pthread_create();
            [23292] | thread_func() {
            [23292] |   execl() {
            [23290] |   main() {
            [23290] |     a() {
            [23290] |       b() {
            [23290] |         c() {
   0.379 us [23290] |           getpid();
   0.772 us [23290] |         } /* c */
   1.159 us [23290] |       } /* b */
   1.289 us [23290] |     } /* a */
   1.461 us [23290] |   } /* main */

uftrace stopped tracing with remaining functions
================================================
task: 23290
[0] main
""")

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'abc', cflags, ldflags)
        ret += TestBase.build(self, self.name, cflags, ldflags + ' -pthread')
        return ret

    def runcmd(self):
        return '%s -N ^__ %s' % (TestBase.uftrace_cmd, 't-' + self.name)
