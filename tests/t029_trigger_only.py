#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'allocfree', """
# DURATION    TID     FUNCTION
 101.601 us [31924] | __monstartup();
   2.047 us [31924] | __cxa_atexit();
            [31924] | main() {
            [31924] |   alloc1() {
            [31924] |     alloc2() {
   3.010 us [31924] |       alloc3();
   4.068 us [31924] |     } /* alloc2 */
   4.611 us [31924] |   } /* alloc1 */
            [31924] |   free1() {
            [31924] |     free2() {
            [31924] |       free3() {
            [31924] |         free4() {
            [31924] |           free5() {
  backtrace [31924] | /* [ 0] main */
  backtrace [31924] | /* [ 1] free1 */
  backtrace [31924] | /* [ 2] free2 */
  backtrace [31924] | /* [ 3] free3 */
  backtrace [31924] | /* [ 4] free4 */
  backtrace [31924] | /* [ 5] free5 */
   1.894 us [31924] |             free();
   2.921 us [31924] |           } /* free5 */
   3.504 us [31924] |         } /* free4 */
   4.059 us [31924] |       } /* free3 */
   4.588 us [31924] |     } /* free2 */
   5.177 us [31924] |   } /* free1 */
  11.175 us [31924] | } /* main */
""")

    def setup(self):
        self.option = '-T "alloc3@depth=1" -T "free@backtrace"'
