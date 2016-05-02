How to install uftrace
======================

The uftrace was written in GNU C and tried to minimize external dependencies.
Currently it requires libelf in elfutils package to build, and there's some
more optional dependencies.

Once you installed required software(s) on your system, it can be built and
installed like following:

    make
    sudo make install

For more advanced setup, please refer INSTALL file.


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

It also support multi-threaded applications.


How to use uftrace
==================
The uftrace command has 5 subcommands: record, replay, report, live, info.

    $ uftrace
    Usage: uftrace [OPTION...] [record|replay|live|report|info] [<command> args...]
    Try `uftrace --help' or `uftrace --usage' for more information.

If omitted, it defaults to the live command which is almost same as running
record and replay subcommand in a row (but does not record the trace info
to files).

For recording, the executable should be compiled with -pg option which
generates profiling code (calling mcount) for each function.

    $ uftrace tests/t-abc
    # DURATION    TID     FUNCTION
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

It'll create uftrace.data directory and contains trace data files.
Other analysis commands expect the directory exists in the current directory,
but one can use another using -f option.

The replay command shows execution information like above.  As you can see,
the t-abc is a very simple program merely calls a, b and c functions.
In the c function it called getpid() which is a library function implemented
in the C library (glibc) on normal systems - the same goes to __cxa_atexit().

The report command lets you know which function spends longest time
including its children (total time).

    $ uftrace report
      Function                          Total time   Self time  Nr. called  
      ================================  ==========  ==========  ==========  
      __cxa_atexit                      464.085 us  464.085 us           1  
      main                                5.560 us    0.734 us           1  
      a                                   4.826 us    0.570 us           1  
      b                                   4.256 us    0.693 us           1  
      c                                   3.563 us    1.180 us           1  
      getpid                              2.383 us    2.383 us           1  

The info command shows system and program information when recorded.

    $ uftrace info
    # ftrace information
    # ==================
    # program version     : uftrace v0.5
    # recorded on         : Mon Aug 11 14:03:52 2014
    # cmdline             : uftrace record tests/t-abc 
    # exe image           : /home/namhyung/project/ftrace/tests/t-abc
    # build id            : 4520d7c12661902a03cc03853219d26aeef0f9cf
    # exit status         : exited with code: 46
    # nr of cpus          : 12/12 (online/possible)
    # cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
    # memory info         : 15.7/31.3 GB (free/total)
    # kernel version      : Linux 3.9.10-100.fc17.x86_64
    # hostname            : sejong.aot.lge.com
    # distro              : "Fedora 17 (Beefy Miracle)"
    # nr of tasks         : 1
    # task list           : 2045


Limitations
===========
- It can only trace a native C/C++ application compiled with -pg option.
- It *cannot* trace already running process.
- It *cannot* be used for system-wide tracing.


License
=======
The ftraceu program is released under GPL v2.  See COPYING file for details.
