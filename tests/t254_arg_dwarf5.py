#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'dwarf5', """
# DURATION     TID     FUNCTION
            [1167172] | main() {
 143.049 us [1167172] |   pass_int1(int1{...}, 1, "2", 3.000000) = 1;
   0.746 us [1167172] |   pass_int3(int3{...}, 1, "2", 3.000000) = 1;
   0.538 us [1167172] |   pass_lng1(lng1{...}, 1, "2", 3.000000) = 1;
   0.492 us [1167172] |   pass_lng3(lng3{...}, 1, "2", 3.000000) = 1;
   0.501 us [1167172] |   pass_dbl1(dbl1{...}, 1, "2", 3.000000) = 1.000000;
   0.351 us [1167172] |   pass_dbl3(dbl3{...}, 1, "2", 3.000000) = 1.000000;
   0.359 us [1167172] |   pass_mix1(mix1{...}, 1, "2", 3.000000) = 0.000000;
   0.387 us [1167172] |   pass_mix2(mix2{...}, 1, "2", 3.000000) = 1.000000;
   0.255 us [1167172] |   pass_mix3(mix3{...}, 1, "2", 3.000000) = 1;
 154.430 us [1167172] | } /* main */

""", cflags='-g')

    def build(self, name, cflags='', ldflags=''):
        if not 'dwarf' in self.feature:
            return TestBase.TEST_SKIP
        if cflags.find('-finstrument-functions') >= 0:
            return TestBase.TEST_SKIP

        return TestBase.build(self, name, cflags, ldflags)

    def setup(self):
        self.option = '-A ^pass -R ^pass -F main'
