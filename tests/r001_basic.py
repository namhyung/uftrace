#!/usr/bin/env python

from runtest import RustTestBase

class TestCase(RustTestBase):
    def __init__(self):
        RustTestBase.__init__(self, 'abc', """
# DURATION     TID     FUNCTION
   1.852 us [1008471] | getauxval();
   0.204 us [1008471] | getauxval();
   0.203 us [1008471] | getauxval();
            [1008471] | std::rt::lang_start() {
  14.260 us [1008471] |   poll();
   5.056 us [1008471] |   signal();
   2.759 us [1008471] |   sigaction();
   2.426 us [1008471] |   sigaction();
   2.537 us [1008471] |   sigaction();
   2.722 us [1008471] |   sigaltstack();
   0.408 us [1008471] |   sysconf();
  13.907 us [1008471] |   mmap64();
   0.260 us [1008471] |   sysconf();
  26.444 us [1008471] |   mprotect();
   0.296 us [1008471] |   sysconf();
   2.019 us [1008471] |   sigaltstack();
   0.185 us [1008471] |   sysconf();
   0.278 us [1008471] |   pthread_self();
 618.405 us [1008471] |   pthread_getattr_np();
   0.389 us [1008471] |   pthread_attr_getstack();
   0.371 us [1008471] |   pthread_attr_destroy();
   0.166 us [1008471] |   malloc();
   0.389 us [1008471] |   malloc();
   4.241 us [1008471] |   __cxa_thread_atexit_impl();
            [1008471] |   std::rt::lang_start::_{{closure}}() {
            [1008471] |     std::sys_common::backtrace::__rust_begin_short_backtrace() {
            [1008471] |       core::ops::function::FnOnce::call_once() {
            [1008471] |         s_abc::main() {
            [1008471] |           s_abc::a() {
            [1008471] |             s_abc::b() {
            [1008471] |               s_abc::c() {
   2.389 us [1008471] |                 getpid();
   4.630 us [1008471] |               } /* s_abc::c */
   5.148 us [1008471] |             } /* s_abc::b */
   5.500 us [1008471] |           } /* s_abc::a */
   5.889 us [1008471] |         } /* s_abc::main */
   6.426 us [1008471] |       } /* core::ops::function::FnOnce::call_once */
   6.908 us [1008471] |     } /* std::sys_common::backtrace::__rust_begin_short_backtrace */
   0.111 us [1008471] |     _<()>::report();
   8.037 us [1008471] |   } /* std::rt::lang_start::_{{closure}} */
   2.408 us [1008471] |   sigaltstack();
   0.259 us [1008471] |   sysconf();
   0.167 us [1008471] |   sysconf();
  41.648 us [1008471] |   munmap();
 780.960 us [1008471] | } /* std::rt::lang_start */
   0.259 us [1008471] | free();
   0.166 us [1008471] | free();
""")
