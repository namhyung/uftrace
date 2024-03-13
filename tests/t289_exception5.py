#!/usr/bin/env python3

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exception5', lang='C++', result="""
# DURATION     TID     FUNCTION
            [289342] | main() {
            [289342] |   f() {
   1.867 us [289342] |     __cxa_guard_acquire();
            [289342] |     A::A() {
   1.739 us [289342] |       __cxa_allocate_exception();
   1.336 us [289342] |       __cxa_guard_abort();
  69.934 us [289342] |     } /* A::A */
   1.085 us [289342] |     __cxa_guard_release();
  77.687 us [289342] |   } /* f */
  78.594 us [289342] | } /* main */
""")
