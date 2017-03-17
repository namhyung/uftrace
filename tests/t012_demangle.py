#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'demangle', lang='C++', result="""
# DURATION    TID     FUNCTION
            [31433] | ABC::foo() {
            [31433] |   __static_initialization_and_destruction_0() {
  96.867 us [31433] |     std::ios_base::Init::Init();
   1.403 us [31433] |     __cxa_atexit();
 101.554 us [31433] |   } /* __static_initialization_and_destruction_0 */
 171.419 us [31433] | } /* ABC::foo */
            [31433] | main() {
   2.540 us [31433] |   operator new();
   0.146 us [31433] |   ABC::ABC();
            [31433] |   ABC::foo() {
            [31433] |     ABC::bar() {
   0.157 us [31433] |       ABC::baz();
   0.714 us [31433] |     } /* ABC::bar */
   1.323 us [31433] |   } /* ABC::foo */
   5.623 us [31433] | } /* main */
   9.223 us [31433] | std::ios_base::Init::~Init();
""")

    def fixup(self, cflags, result):
        return result.replace(" std::ios_base::Init::~Init();\n", '')
