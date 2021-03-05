#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [22757] | main() {
   2.554 us [22757] |   operator new(unsigned long);
   1.040 us [22757] |   ns::ns1::foo::foo(int);
            [22757] |   ns::ns1::foo::bar() {
            [22757] |     ns::ns1::foo::bar1() {
            [22757] |       ns::ns1::foo::bar2() {
            [22757] |         ns::ns1::foo::bar3() {
   1.360 us [22757] |           malloc();
   1.903 us [22757] |         } /* ns::ns1::foo::bar3() */
   2.276 us [22757] |       } /* ns::ns1::foo::bar2() */
   2.629 us [22757] |     } /* ns::ns1::foo::bar1() */
   1.266 us [22757] |     free();
   4.629 us [22757] |   } /* ns::ns1::foo::bar() */
   1.927 us [22757] |   operator delete(void*);
   0.283 us [22757] |   operator new(unsigned long);
   0.223 us [22757] |   operator delete(void*);
  76.629 us [22757] | } /* main */
""")

    def setup(self):
        self.option = '--demangle=full -N "ns2.*"'

    def fixup(self, cflags, result):
        if TestBase.is_32bit(self):
            return result.replace('unsigned long', 'unsigned int')

        return result.replace('delete(void*);',
                              'delete(void*, unsigned long);')
