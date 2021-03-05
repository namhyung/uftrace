[![Build Status](https://travis-ci.org/namhyung/uftrace.svg?branch=master)](https://travis-ci.org/namhyung/uftrace)
[![Coverity scan](https://scan.coverity.com/projects/12421/badge.svg)](https://scan.coverity.com/projects/namhyung-uftrace)

uftrace
=======

The uftrace tool is to trace and analyze execution of a program
written in C/C++.  It was heavily inspired by the ftrace framework
of the Linux kernel (especially function graph tracer) and supports
userspace programs.  It supports various kind of commands and filters
to help analysis of the program execution and performance.

![uftrace-live-demo](doc/uftrace-live-demo.gif)

 * Homepage: https://github.com/namhyung/uftrace
 * Tutorial: https://github.com/namhyung/uftrace/wiki/Tutorial
 * Chat: https://gitter.im/uftrace/uftrace
 * Mailing list: [uftrace@googlegroups.com](https://groups.google.com/forum/#!forum/uftrace)


Features
========

It traces each function in the executable and shows time duration.  It
can also trace external library calls - but usually entry and exit are
supported.  Optionally it's possible to trace other (nested) external
library calls and/or internal function calls in the library call.

It can show detailed execution flow at function level, and report which
function has the highest overhead.  And it also shows various information
related the execution environment.

You can setup filters to exclude or include specific functions when tracing.
In addition, it can save and show function arguments and return value.

It supports multi-process and/or multi-threaded applications.  With root
privilege, it can also trace kernel functions as well( with `-k` option)
if the system enables the function graph tracer in the kernel
(`CONFIG_FUNCTION_GRAPH_TRACER=y`).


How to build and install uftrace
================================

On Linux distros, [misc/install-deps.sh](misc/install-deps.sh) installs required
software(s) on your system.  Those are for optional advanced features but highly
recommend to install them together.

    $ sudo misc/install-deps.sh

Once you installed required software(s) on your system, it can be built and
installed like following:

    $ ./configure
    $ make
    $ sudo make install

For more advanced setup, please refer [INSTALL.md](INSTALL.md) file.


How to use uftrace
==================
The uftrace command has following subcommands:

 * `record` : runs a program and saves the trace data
 * `replay` : shows program execution in the trace data
 * `report` : shows performance statistics in the trace data
 * `live`   : does record and replay in a row (default)
 * `info`   : shows system and program info in the trace data
 * `dump`   : shows low-level trace data
 * `recv`   : saves the trace data from network
 * `graph`  : shows function call graph in the trace data
 * `script` : runs a script for recorded trace data
 * `tui`    : show text user interface for graph and report

You can use `-h`, `-?` or `--help` option to see available commands and options.

    $ uftrace
    Usage: uftrace [OPTION...]
                [record|replay|live|report|info|dump|recv|graph|script|tui] [<program>]
    Try `uftrace --help' or `uftrace --usage' for more information.

If omitted, it defaults to the `live` command which is almost same as running
record and replay subcommand in a row (but does not record the trace info
to files).

For recording, the executable needs to be compiled with the `-pg`
(or `-finstrument-functions`) option which generates profiling code
(calling mcount or __cyg_profile_func_enter/exit) for each function.

Note that, there's an experimental support for dynamic tracing on
x86_64 and AArch64(ARM64) which doesn't require such (re-)compilations.
Also recent compilers have some options to help uftrace
to reduce tracing overhead with similar way
(although it still needs recompilation of your program).
Please see [dynamic tracing](doc/uftrace-record.md#dynamic-tracing) section
for more details.

    $ uftrace tests/t-abc
    # DURATION    TID     FUNCTION
      16.134 us [ 1892] | __monstartup();
     223.736 us [ 1892] | __cxa_atexit();
                [ 1892] | main() {
                [ 1892] |   a() {
                [ 1892] |     b() {
                [ 1892] |       c() {
       2.579 us [ 1892] |         getpid();
       3.739 us [ 1892] |       } /* c */
       4.376 us [ 1892] |     } /* b */
       4.962 us [ 1892] |   } /* a */
       5.769 us [ 1892] | } /* main */

For more analysis, you'd be better recording it first so that it can run
analysis commands like replay, report, graph, dump and/or info multiple times.

    $ uftrace record tests/t-abc

It'll create uftrace.data directory that contains trace data files.
Other analysis commands expect the directory exists in the current directory,
but one can use another using `-d` option.

The `replay` command shows execution information like above.  As you can see,
the t-abc is a very simple program merely calls a, b and c functions.
In the c function it called getpid() which is a library function implemented
in the C library (glibc) on normal systems - the same goes to __cxa_atexit().

Users can use various filter options to limit functions it records/prints.
The depth filter (`-D` option) is to omit functions under the given call depth.
The time filter (`-t` option) is to omit functions running less than the given
time. And the function filters (`-F` and `-N` options) are to show/hide functions
under the given function.

The `-k` option enables to trace kernel functions as well (needs root access).
With the classic hello world program, the output would look like below (Note,
I changed it to use fprintf() with stderr rather than the plain printf() to make
it invoke system call directly):

    $ sudo uftrace -k tests/t-hello
    Hello world
    # DURATION    TID     FUNCTION
       1.365 us [21901] | __monstartup();
       0.951 us [21901] | __cxa_atexit();
                [21901] | main() {
                [21901] |   fprintf() {
       3.569 us [21901] |     __do_page_fault();
      10.127 us [21901] |     sys_write();
      20.103 us [21901] |   } /* fprintf */
      21.286 us [21901] | } /* main */

You can see the page fault handler and the write syscall handler were called
inside the fprintf() call.

Also it can record and show function arguments and return value with `-A` and
`-R` options respectively.  The following example records first argument and
return value of 'fib' (fibonacci number) function.

    $ uftrace record -A fib@arg1 -R fib@retval tests/t-fibonacci 5

    $ uftrace replay
    # DURATION    TID     FUNCTION
       2.853 us [22080] | __monstartup();
       2.194 us [22080] | __cxa_atexit();
                [22080] | main() {
       2.706 us [22080] |   atoi();
                [22080] |   fib(5) {
                [22080] |     fib(4) {
                [22080] |       fib(3) {
       7.473 us [22080] |         fib(2) = 1;
       0.419 us [22080] |         fib(1) = 1;
      11.452 us [22080] |       } = 2; /* fib */
       0.460 us [22080] |       fib(2) = 1;
      13.823 us [22080] |     } = 3; /* fib */
                [22080] |     fib(3) {
       0.424 us [22080] |       fib(2) = 1;
       0.437 us [22080] |       fib(1) = 1;
       2.860 us [22080] |     } = 2; /* fib */
      19.600 us [22080] |   } = 5; /* fib */
      25.024 us [22080] | } /* main */

The `report` command lets you know which function spends the longest time
including its children (total time).

    $ uftrace report
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================================
       25.024 us    2.718 us           1  main
       19.600 us   19.600 us           9  fib
        2.853 us    2.853 us           1  __monstartup
        2.706 us    2.706 us           1  atoi
        2.194 us    2.194 us           1  __cxa_atexit


The `graph` command shows function call graph of given function.  In the above
example, function graph of function 'main' looks like below:

    $ uftrace graph  main
    # Function Call Graph for 'main' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 1, time  25.024 us
       [0] main (0x40066b)
    
    ========== FUNCTION CALL GRAPH ==========
      25.024 us : (1) main
       2.706 us :  +-(1) atoi
                :  | 
      19.600 us :  +-(1) fib
      16.683 us :    (2) fib
      12.773 us :    (4) fib
       7.892 us :    (2) fib


The `dump` command shows raw output of each trace record.  You can see the result
in the chrome browser, once the data is processed with `uftrace dump --chrome`.
Below is a trace of clang (LLVM) compiling a small C++ template metaprogram.

[![uftrace-chrome-dump](doc/uftrace-chrome.png)](https://uftrace.github.io/dump/clang.tmp.fib.html)

It also supports flame-graph output as well.  The data can be processed with
`uftrace dump --flame-graph` and passed to
[flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/master/flamegraph.pl).
Below is a flame graph result of gcc compiling a simple C program.

[![uftrace-flame-graph-dump](https://uftrace.github.io/dump/gcc.svg)](https://uftrace.github.io/dump/gcc.svg)

The `info` command shows system and program information when recorded.

    $ uftrace info
    # system information
    # ==================
    # program version     : uftrace v0.8.1
    # recorded on         : Tue May 24 11:21:59 2016
    # cmdline             : uftrace record tests/t-abc 
    # cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
    # number of cpus      : 12 / 12 (online / possible)
    # memory info         : 20.1 / 23.5 GB (free / total)
    # system load         : 0.00 / 0.06 / 0.06 (1 / 5 / 15 min)
    # kernel version      : Linux 4.5.4-1-ARCH
    # hostname            : sejong
    # distro              : "Arch Linux"
    #
    # process information
    # ===================
    # number of tasks     : 1
    # task list           : 5098
    # exe image           : /home/namhyung/project/uftrace/tests/t-abc
    # build id            : a3c50d25f7dd98dab68e94ef0f215edb06e98434
    # exit status         : exited with code: 0
    # elapsed time        : 0.003219479 sec
    # cpu time            : 0.000 / 0.003 sec (sys / user)
    # context switch      : 1 / 1 (voluntary / involuntary)
    # max rss             : 3072 KB
    # page fault          : 0 / 172 (major / minor)
    # disk iops           : 0 / 24 (read / write)

The `script` command allows user to run a custom script on a data recorded.
The supported script types are Python 2.7 and Lua 5.1 as of now.

The `tui` command is for interactive text-based user interface using ncurses.
It provides basic functionality of `graph`, `report` and `info` commands as of
now.


Limitations
===========
- It can trace a native C/C++ application on Linux.
- It *cannot* trace already running process.
- It *cannot* be used for system-wide tracing.
- It supports x86 (32 and 64 bit), ARM (v6 or later) and AArch64 for now.


License
=======
The uftrace program is released under GPL v2.  See [COPYING file](COPYING) for details.
