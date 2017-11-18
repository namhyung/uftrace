% UFTRACE-INFO(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% May, 2016

NAME
====
uftrace-info - Print tracing information for trace data

SYNOPSIS
========
uftrace info [*options*] [*COMMAND*]

DESCRIPTION
===========
This command prints metadata recorded in the header of a given data file.

OPTIONS
=======
\--symbols
:   Print symbols table instead of the recorded tracing info.  It will print two symbol tables - normal symbols and dynamic symbols.  The normal symbols are from the executable itself, and dynamic symbols are for library calls.   When COMMAND is given, it should provide symbol information which might not be available from the recorded path of 'exe image' or the symbol file in the data directory.


EXAMPLE
=======
This command shows information like below:

    $ uftrace record abc

    $ uftrace info
    # system information
    # ==================
    # program version     : uftrace v0.5-191-g30a3
    # recorded on         : Tue May 24 15:59:00 2016
    # cmdline             : uftrace record abc
    # cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
    # number of cpus      : 12 / 12 (online / possible)
    # memory info         : 19.8 / 23.5 GB (free / total)
    # system load         : 0.02 / 0.07 / 0.11 (1 / 5 / 15 min)
    # kernel version      : Linux 4.5.4-1-ARCH
    # hostname            : sejong
    # distro              : "Arch Linux"
    #
    # process information
    # ===================
    # number of tasks     : 1
    # task list           : 8284
    # exe image           : /home/namhyung/tmp/abc
    # build id            : a3c50d25f7dd98dab68e94ef0f215edb06e98434
    # exit status         : exited with code: 0
    # elapsed time        : 0.003219479 sec
    # cpu time            : 0.003 / 0.000 sec (sys / user)
    # context switch      : 1 / 1 (voluntary / involuntary)
    # max rss             : 3104 KB
    # page fault          : 0 / 169 (major / minor)
    # disk iops           : 0 / 24 (read / write)

To see the symbol table, one can use the `--symbols` option.

    $ uftrace info --symbols
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


You can get symbol information from ELF binary directly without trace data.

    $ uftrace info --symbols abc
    Normal symbols
    ==============
    [ 0] 0x3e0: main (size: 144)
    [ 1] 0x470: __x86.get_pc_thunk.bx (size: 203)
    [ 2] 0x53b: c (size: 57)
    [ 3] 0x574: b (size: 50)
    [ 4] 0x5a6: a (size: 58)
    [ 5] 0x5e0: __libc_csu_init (size: 96)
    [ 6] 0x640: __libc_csu_fini (size: 2)
    [ 7] 0x642: __sym_end (size: 0)


    Dynamic symbols
    ===============
    [ 0] 0x380: __cyg_profile_func_enter (size: 16)
    [ 1] 0x390: __cyg_profile_func_exit (size: 16)
    [ 2] 0x3a0: getpid (size: 16)
    [ 3] 0x3b0: __libc_start_main (size: 16)
    [ 4] 0x3c0: atoi (size: 16)
    [ 5] 0x3d0: __dynsym_end (size: 0)


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1)
