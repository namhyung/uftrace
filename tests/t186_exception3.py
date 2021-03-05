#!/usr/bin/env python

from runtest import TestBase

class TestCase(TestBase):
    def __init__(self):
        TestBase.__init__(self, 'exception3', lang='C++', result="""
# DURATION     TID     FUNCTION
            [ 16014] | main() {
   0.205 us [ 16014] |   A::A();
            [ 16014] |   foo() {
            [ 16014] |     foo1() {
            [ 16014] |       foo2() {
            [ 16014] |         foo3() {
            [ 16014] |           foo4() {
   0.130 us [ 16014] |             C::C();
            [ 16014] |             foo5() {
   2.142 us [ 16014] |               __cxa_allocate_exception();
  34.096 us [ 16014] |             } /* foo5 */
   0.087 us [ 16014] |             C::~C();
  41.512 us [ 16014] |           } /* foo4 */
  56.240 us [ 16014] |         } /* foo3 */
  56.506 us [ 16014] |       } /* foo2 */
  56.817 us [ 16014] |     } /* foo1 */
   0.088 us [ 16014] |     B::B();
   0.087 us [ 16014] |     B::~B();
  67.679 us [ 16014] |   } /* foo */
   0.085 us [ 16014] |   A::~A();
            [ 16014] |   catch_exc() {
            [ 16014] |     bar() {
   0.088 us [ 16014] |       B::B();
            [ 16014] |       bar1() {
            [ 16014] |         bar2() {
            [ 16014] |           bar3() {
   0.080 us [ 16014] |             C::C();
   0.431 us [ 16014] |             __cxa_allocate_exception();
   0.092 us [ 16014] |             C::~C();
  12.139 us [ 16014] |           } /* bar3 */
  12.345 us [ 16014] |         } /* bar2 */
  12.543 us [ 16014] |       } /* bar1 */
   0.096 us [ 16014] |       B::~B();
            [ 16014] |       catch_exc() {
   0.086 us [ 16014] |         baz();
   0.461 us [ 16014] |       } /* catch_exc */
  14.698 us [ 16014] |     } /* bar */
  14.948 us [ 16014] |   } /* catch_exc */
  85.226 us [ 16014] | } /* main */
""")

    def setup(self):
        self.option = '-N personality_v.'
