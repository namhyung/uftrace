#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'signal', """
# DURATION     TID     FUNCTION
            [ 11892] | main() {
   0.241 us [ 11892] |   foo();
   1.611 us [ 11892] |   signal();
            [ 11892] |   raise() {
            [ 11892] |     sighandler() {
   0.120 us [ 11892] |       bar();
   2.315 us [ 11892] |     } /* sighandler */

uftrace stopped tracing with remaining functions
================================================
task: 11892
[2] sighandler
[1] raise
[0] main
""")

    def setup(self):
        self.option = "--signal SIGUSR1@finish"

    def fixup(self, cflags, result):
        return result.replace("""     } /* sighandler */
""", "")
