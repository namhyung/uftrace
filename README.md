How to install uftrace
======================

The uftrace is written in C and tried to minimize external dependencies.
Currently it requires libelf in elfutils package to build, and there're some
more optional dependencies.

Once you installed required software(s) on your system, it can be built and
installed like following:

    make
    sudo make install

For more advanced setup, please refer INSTALL.md file.


Features
========

It traces each function in the executable and shows time duration.  It
can also trace external library calls - but only entry and exit are
supported and cannot trace internal function calls in the library call
unless the library itself built with profiling enabled.

It can show detailed execution flow at function level, and report which
function has highest overhead.  And it also shows various information
related the execution environment.

You can setup a filter to exclude or include specific functions when tracing.

It also supports multi-process and/or multi-threaded applications.


How to use uftrace
==================
The uftrace command has 5 subcommands: record, replay, report, live, info.

    $ uftrace
    Usage: uftrace [OPTION...] [record|replay|live|report|info] [<command> args...]
    Try `uftrace --help' or `uftrace --usage' for more information.

If omitted, it defaults to the live command which is almost same as running
record and replay subcommand in a row (but does not record the trace info
to files).

For recording, the executable should be compiled with -pg
(or -finstrument-functions) option which generates profiling code
(calling mcount or __cyg_profile_func_enter/exit) for each function.

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
analysis commands like replay, report and/or info multiple times.

    $ uftrace record tests/t-abc

It'll create uftrace.data directory that contains trace data files.
Other analysis commands expect the directory exists in the current directory,
but one can use another using -d option.

The replay command shows execution information like above.  As you can see,
the t-abc is a very simple program merely calls a, b and c functions.
In the c function it called getpid() which is a library function implemented
in the C library (glibc) on normal systems - the same goes to __cxa_atexit().

The report command lets you know which function spends longest time
including its children (total time).

    $ uftrace report
      Total time   Self time  Nr. called  Function
      ==========  ==========  ==========  ====================================
        2.723 us    0.337 us           1  main
        2.386 us    0.330 us           1  a
        2.056 us    0.366 us           1  b
        1.690 us    0.927 us           1  c
        1.277 us    1.277 us           1  __monstartup
        0.936 us    0.936 us           1  __cxa_atexit
        0.763 us    0.763 us           1  getpid


The info command shows system and program information when recorded.

    $ uftrace info
    # system information
    # ==================
    # program version     : uftrace v0.6
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
    # exe image           : /home/namhyung/project/ftrace/tests/t-abc
    # build id            : a3c50d25f7dd98dab68e94ef0f215edb06e98434
    # exit status         : exited with code: 0
    # cpu time            : 0.000 / 0.003 sec (sys / user)
    # context switch      : 1 / 1 (voluntary / involuntary)
    # max rss             : 3072 KB
    # page fault          : 0 / 172 (major / minor)
    # disk iops           : 0 / 24 (read / write)


Limitations
===========
- It can only trace a native C/C++ application compiled with -pg option.
- It *cannot* trace already running process.
- It *cannot* be used for system-wide tracing.


License
=======
The uftrace program is released under GPL v2.  See COPYING file for details.
