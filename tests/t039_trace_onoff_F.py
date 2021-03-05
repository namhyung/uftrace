#!/usr/bin/env python

from runtest import TestBase

# Unlike filters (-F), The trace-on/off trigger preserves the depth.
class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'namespace', lang="C++", result="""
# DURATION    TID     FUNCTION
            [27770] |       ns::ns1::foo::bar3() {
   2.725 us [27770] |         malloc();
  78.805 us [27770] |       } /* ns::ns1::foo::bar3 */
            [27770] |     } /* ns::ns1::foo::bar2 */
            [27770] |   } /* ns::ns1::foo::bar1 */
   1.791 us [27770] |   free();
            [27770] | } /* ns::ns1::foo::bar */
""", sort='simple')

    def setup(self):
        self.option = '--disable -F "ns::ns1::foo::bar" -T ".*foo::bar3@trace_on"'
