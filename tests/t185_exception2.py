#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exception2', lang='C++', result="""
# DURATION     TID     FUNCTION
            [ 25279] | _GLOBAL__sub_I__Z3foov() {
            [ 25279] |   __static_initialization_and_destruction_0() {
  51.124 us [ 25279] |     std::ios_base::Init::Init();
  55.299 us [ 25279] |   } /* __static_initialization_and_destruction_0 */
  55.864 us [ 25279] | } /* _GLOBAL__sub_I__Z3foov */
            [ 25279] | main() {
   0.050 us [ 25279] |   foo() {
   1.513 us [ 25279] |     __cxa_allocate_exception();
  22.451 us [ 25279] |   } /* foo */
   0.087 us [ 25279] |   bar();
  23.092 us [ 25279] | } /* main */
""")

    def setup(self):
        self.option = '-N personality_v.'
