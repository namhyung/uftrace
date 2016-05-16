% UFTRACE-REPORT(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
uftrace-report - Print statistics and summary for trace data

SYNOPSIS
========
uftrace report [*options*]

DESCRIPTION
===========
This command collects trace data from a given data file and prints statistics and summary information.  It shows function statistics by default, but can show threads statistics with `--threads` option.

OPTIONS
=======
-f *FILE*, \--file=*FILE*
:   Use this filename for trace data.  Default is `uftrace.data`.

\--threads
:   Report thread summary information rather than function statistics.

\--no-pager
:   Do not use pager

-s *KEYS*[,*KEYS*,...], \--sort=*KEYS*[,*KEYS*,...]
:   Sort functions by given KEYS.  Multiple KEYS can be given, separated by comma (,).  Possible keys are 'total' (time), 'self' (time), 'call', 'avg', 'min', 'max'.  Note that first 3 keys should be used when neither of '--avg-total' nor '--avg-self' is used.  Likewise, the last 3 keys should be used when either of those option is used.

\--avg-total
:   Show average, min, max of each functions total time.

\--avg-self
:   Show average, min, max of each functions self time.

\--color=*VAL*
:   Enable or disable color on the output.  Possible values are "yes", "no" and "auto".  The "auto" is default and turn on coloring if stdout is a terminal.

\--demangle=*TYPE*
:   Demangle C++ symbol names.  Possible values are "full", "simple" and "no".  Default is "simple" which ignores function arguments and template parameters.

\--diff=*DATA*
:   Report difference between the input trace data and the given DATA.

\--sort-column=*IDX*
:   When --diff option is used, 3 columns will be shown for each total time, self time and call count.  This is option is to select the index of column to be used as a sort key.

EXAMPLE
=======
This command shows information like below:

    $ uftrace record abc
    $ uftrace report
      Total time   Self time  Nr. called     Function
      ==========  ==========  ==========  =======================================
      150.829 us  150.829 us           1  __cxa_atexit
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b
       24.173 us    1.715 us           1  c
       22.458 us   22.458 us           1  getpid

    $ uftrace report -s call,self
      Total time   Self time  Nr. called     Function
      ==========  ==========  ==========  =======================================
      150.829 us  150.829 us           1  __cxa_atexit
       22.458 us   22.458 us           1  getpid
       24.173 us    1.715 us           1  c
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b

    $ uftrace report --avg-self
        Avg self    Min self    Max self  Function
      ==========  ==========  ==========  =======================================
      150.829 us  150.829 us  150.829 us  __cxa_atexit
       22.458 us   22.458 us   22.458 us  getpid
        1.715 us    1.715 us    1.715 us  c
        1.243 us    1.243 us    1.243 us  main
        0.939 us    0.939 us    0.939 us  a
        0.934 us    0.934 us    0.934 us  b

    $ uftrace report --threads
        TID  Start function                              Run time   Nr. funcs
      =====  ========================================  ==========  ==========
      21959  main                                      178.118 us           6
	
SEE ALSO
========
`uftrace`(1), `uftrace-record`(1)
