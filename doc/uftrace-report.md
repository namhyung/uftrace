% UFTRACE-REPORT(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% May, 2016

NAME
====
uftrace-report - Print statistics and summary for trace data


SYNOPSIS
========
uftrace report [*options*]


DESCRIPTION
===========
This command collects trace data from a given data file and prints statistics and summary information.  It shows function statistics by default, but can show threads statistics with `--threads` option and show differences to given data with `--diff` option.


OPTIONS
=======
\--threads
:   Report thread summary information rather than function statistics.

-s *KEYS*[,*KEYS*,...], \--sort=*KEYS*[,*KEYS*,...]
:   Sort functions by given KEYS.  Multiple KEYS can be given, separated by comma (,).  Possible keys are 'total' (time), 'self' (time), 'call', 'avg', 'min', 'max'.  Note that first 3 keys should be used when neither of '--avg-total' nor '--avg-self' is used.  Likewise, the last 3 keys should be used when either of those option is used.

\--avg-total
:   Show average, min, max of each functions total time.

\--avg-self
:   Show average, min, max of each functions self time.

\--diff=*DATA*
:   Report difference between the input trace data and the given DATA.

\--sort-column=*IDX*
:   When --diff option is used, 3 columns will be shown for each total time, self time and call count.  This is option is to select the index of column to be used as a sort key.  The index 0 is for original data given by --file option, and index 1 is for data given by --diff option, and index 2 is for (percentage of) difference between the two data.

-k, \--kernel
:   Trace kernel functions as well as user functions.  Only kernel functions inside user functions will be shown.

--kernel-full
:   Show all kernel functions called outside of user functions.  Implies \--kernel option.


EXAMPLE
=======
This command shows information like below:

    $ uftrace record abc
    $ uftrace report
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  =======================================
      150.829 us  150.829 us           1  __cxa_atexit
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b
       24.173 us    1.715 us           1  c
       22.458 us   22.458 us           1  getpid

    $ uftrace report -s call,self
      Total time   Self time       Calls  Function
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
        TID    Run time   Num funcs  Start function
      =====  ==========  ==========  ====================================
      21959  178.118 us           6  main

    $ uftrace record abc
    $ uftrace report --diff uftrace.data.old
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
                     Total time (diff)                   Self time (diff)                  Nr. called (diff)   Function
      ================================   ================================   ================================   ====================================
        2.812 us    2.511 us   -10.70%     0.403 us    0.365 us    -9.43%            1          1         +0   main
        2.409 us    2.146 us   -10.92%     0.342 us    0.272 us   -20.47%            1          1         +0   a
        2.067 us    1.874 us    -9.34%     0.410 us    0.368 us   -10.24%            1          1         +0   b
        1.657 us    1.506 us    -9.11%     0.890 us    0.800 us   -10.11%            1          1         +0   c
        0.920 us    0.789 us   -14.24%     0.920 us    0.789 us   -14.24%            1          1         +0   __cxa_atexit
        0.767 us    0.706 us    -7.95%     0.767 us    0.706 us    -7.95%            1          1         +0   getpid

    $ uftrace report --diff uftrace.data.old -s self --sort-column 2
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
                     Total time (diff)                   Self time (diff)                  Nr. called (diff)   Function
      ================================   ================================   ================================   ====================================
        0.767 us    0.706 us    -7.95%     0.767 us    0.706 us    -7.95%            1          1         +0   getpid
        2.812 us    2.511 us   -10.70%     0.403 us    0.365 us    -9.43%            1          1         +0   main
        1.657 us    1.506 us    -9.11%     0.890 us    0.800 us   -10.11%            1          1         +0   c
        2.067 us    1.874 us    -9.34%     0.410 us    0.368 us   -10.24%            1          1         +0   b
        0.920 us    0.789 us   -14.24%     0.920 us    0.789 us   -14.24%            1          1         +0   __cxa_atexit
        2.409 us    2.146 us   -10.92%     0.342 us    0.272 us   -20.47%            1          1         +0   a

In the above example, the result was sorted by percentage of difference of self times.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1)
