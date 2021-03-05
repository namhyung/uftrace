#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
   3.937 us [  447] | __monstartup();
   1.909 us [  447] | __cxa_atexit();
            [  447] | main() {
            [  447] |   alloc1() {
            [  447] |     alloc2() {
            [  447] |       alloc3() {
            [  447] |         alloc4() {
            [  447] |           alloc5() {
   8.408 us [  447] |             malloc(1);
  10.642 us [  447] |           } /* alloc5 */
  11.502 us [  447] |         } /* alloc4 */
  12.057 us [  447] |       } /* alloc3 */
  12.780 us [  447] |     } /* alloc2 */
  13.400 us [  447] |   } /* alloc1 */
            [  447] |   free1() {
            [  447] |     free2() {
            [  447] |       free3() {
            [  447] |         free4() {
            [  447] |           free5() {
   2.072 us [  447] |             free();
   3.951 us [  447] |           } /* free5 */
   4.561 us [  447] |         } /* free4 */
   5.151 us [  447] |       } /* free3 */
   5.713 us [  447] |     } /* free2 */
   6.341 us [  447] |   } /* free1 */
  21.174 us [  447] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A "alloc*@PLT,arg1"'
