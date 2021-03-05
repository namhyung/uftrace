#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'std-string', lang='C++', result="""
# DURATION    TID     FUNCTION
            [71555] | main() {
   7.549 us [71555] |   std_string_arg("Hello"s);
   0.218 us [71555] |   std_string_arg("World!"s);
   0.150 us [71555] |   std_string_arg("std::string support is done!"s);
   0.240 us [71555] |   std_string_ret::cxx11() = "Hello"s;
   0.124 us [71555] |   std_string_ret::cxx11() = "World!"s;
   0.110 us [71555] |   std_string_ret::cxx11() = "std::string support is done!"s;
  10.346 us [71555] | } /* main */
""")

    def build(self, name, cflags='', ldflags=''):
        # cygprof doesn't support arguments now
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    # To handle g++ 4.xx version
    def fixup(self, cflags, result):
        return result.replace("std_string_ret::cxx11()", "std_string_ret()")

    def setup(self):
        self.option  = '-A ^std_string_arg@arg1/S '
        self.option += '-R ^std_string_ret@retval/S '
        self.option += '-F main -F ^std_string_ -D 1'
