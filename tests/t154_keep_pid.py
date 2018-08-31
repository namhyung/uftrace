from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'daemon', """
# DURATION    TID     FUNCTION
            [22067] | main() {
            [22067] |   daemon() {
            [22072] |   } /* daemon */
            [22072] |   a() {
            [22072] |     b() {
            [22072] |       c() {
   1.196 us [22072] |         getpid();
   3.268 us [22072] |       } /* c */
   3.555 us [22072] |     } /* b */
   3.798 us [22072] |   } /* a */
  22.759 us [22072] | } /* main */

uftrace stopped tracing with remaining functions
================================================
task: 22067
[1] daemon
[0] main
""")

    def runcmd(self):
        uftrace = TestBase.uftrace_cmd
        options = '--keep-pid --no-pager'
        program ='t-' + self.name
        return '%s %s %s' % (uftrace, options, program)
