% FTRACE-INFO(1) Ftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
ftrace-info - Print tracing information for trace data

SYNOPSIS
========
ftrace info [*options*] [*COMMAND*]

DESCRIPTION
===========
This command prints metadata recorded in the header of a given data file.  When COMMAND is given, it should provides symbol information which might not be available from the recorded path of 'exe image'.

OPTIONS
=======
-f *FILE*, \--file=*FILE*
:   Use this filename for trace data.  Default is `ftrace.dir`.

\--symbols
:   Print symbols table instead of the recorded tracing info.  It will print two symbols tables - normal symbols and dynamic symbols.  The normal symbols are from the executable itself, and dynamic symbols are for library calls.

\--no-pager
:   Do not use pager

EXAMPLE
=======
This command shows information like below:

    $ ftrace record abc

    $ ftrace info
    # ftrace information
    # ==================
    # program version     : ftrace v0.2
    # recorded on         : Thu Mar  5 12:08:46 2015
    # cmdline             : ftrace record abc
    # exe image           : /home/namhyung/tmp/abc
    # build id            : 5d7e716244b178f4eea9c5fd82d2f822459e7080
    # exit status         : exited with code: 192
    # nr of cpus          : 4/4 (online/possible)
    # cpu info            : Intel(R) Core(TM) i7-2640M CPU @ 2.80GHz
    # memory info         : 0.1/15.5 GB (free/total)
    # kernel version      : Linux 3.18.6-1-ARCH
    # hostname            : danjae
    # distro              : "Arch Linux"
    # nr of tasks         : 1
    # task list           : 21959

To see symbol table, one can use \--symbols option.

    $ ftrace info --symbols
    Normal symbols
    ==============
    [ 0] _start (0x400590) size: 42
    [ 1] __gmon_start__ (0x4005c0) size: 59
    [ 2] a (0x4006c6) size: 19
    [ 3] b (0x4006d9) size: 19
    [ 4] c (0x4006ec) size: 49
    [ 5] main (0x40071d) size: 19
    [ 6] __libc_csu_init (0x400730) size: 101
    [ 7] __libc_csu_fini (0x4007a0) size: 2
    [ 8] atexit (0x4007b0) size: 41

    Dynamic symbols
    ===============
    [ 0] getpid (0x400530) size: 16
    [ 1] _mcleanup (0x400540) size: 16
    [ 2] __libc_start_main (0x400550) size: 16
    [ 3] __monstartup (0x400560) size: 16
    [ 4] mcount (0x400570) size: 16
    [ 5] __cxa_atexit (0x400580) size: 16

SEE ALSO
========
`ftrace`(1), `ftrace-record`(1)
