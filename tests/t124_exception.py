#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exception', lang='C++', result="""
# DURATION    TID     FUNCTION
   2.777 us [10827] | __cxa_atexit();
            [10827] | foo() {
            [10827] |   __static_initialization_and_destruction_0() {
 108.818 us [10827] |     std::ios_base::Init::Init();
   0.350 us [10827] |     __cxa_atexit();
 111.039 us [10827] |   } /* __static_initialization_and_destruction_0 */
 111.488 us [10827] | } /* foo */
            [10827] | main() {
   0.078 us [10827] |   foo();
            [10827] |   test() {
            [10827] |     oops() {
   1.752 us [10827] |       __cxa_allocate_exception();
   0.088 us [10827] |       std::exception::exception();
   9.640 us [10827] |       __gxx_personality_v0();
   9.640 us [10827] |       __gxx_personality_v0();
   9.640 us [10827] |       __gxx_personality_v0();
  84.367 us [10827] |     } /* oops */
   9.640 us [10827] |     __gxx_personality_v0();
   1.903 us [10827] |     __gxx_personality_v0();
   0.873 us [10827] |     std::exception::~exception();
  84.652 us [10827] |   } /* test */
   0.090 us [10827] |   bar();
  85.590 us [10827] | } /* main */
   2.352 us [10827] | std::ios_base::Init::~Init();
""")
