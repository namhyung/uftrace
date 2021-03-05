#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'vforkexec', """
# DURATION    TID     FUNCTION
            [ 3122] | main() {
            [ 3122] |   vfork() {
            [ 3124] |   } /* vfork */
            [ 3124] |   execl() {
   1.248 ms [ 3122] |   } /* vfork */
            [ 3122] |   wait() {
            [ 3124] | main() {
            [ 3124] |   a() {
            [ 3124] |     b() {
            [ 3124] |       c() {
   1.655 us [ 3124] |         getpid();
   3.861 us [ 3124] |       } /* c */
   4.393 us [ 3124] |     } /* b */
   4.901 us [ 3124] |   } /* a */
   7.511 us [ 3124] | } /* main */
   2.706 ms [ 3122] |   } /* wait */
   3.959 ms [ 3122] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        ret  = TestBase.build(self, 'abc', cflags, ldflags)
        ret += TestBase.build(self, self.name, cflags, ldflags)
        return ret

    def setup(self):
        self.option = '-F main'
