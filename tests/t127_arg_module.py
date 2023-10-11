#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
   2.417 us [32130] | __monstartup();
   1.535 us [32130] | __cxa_atexit();
            [32130] | main() {
            [32130] |   alloc1(1) {
            [32130] |     alloc2(1) {
            [32130] |       alloc3(1) {
            [32130] |         alloc4(1) {
            [32130] |           alloc5(1) {
   1.850 us [32130] |             malloc(1);
   4.284 us [32130] |           } /* alloc5 */
  11.517 us [32130] |         } /* alloc4 */
  12.357 us [32130] |       } /* alloc3 */
  13.036 us [32130] |     } /* alloc2 */
  14.543 us [32130] |   } /* alloc1 */
            [32130] |   free1() {
            [32130] |     free2() {
            [32130] |       free3() {
            [32130] |         free4() {
            [32130] |           free5() {
   1.394 us [32130] |             free();
   2.970 us [32130] |           } /* free5 */
   3.531 us [32130] |         } /* free4 */
   4.064 us [32130] |       } /* free3 */
   4.641 us [32130] |     } /* free2 */
   5.271 us [32130] |   } /* free1 */
  21.319 us [32130] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A "alloc*@t-allocfree,arg1"'
