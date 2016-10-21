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
This command collects trace data from a given data file and prints statistics and summary information.  It shows function statistics by default, but can show thread statistics with the `--threads` option and show differences between traces with the `--diff` option.


OPTIONS
=======
\--threads
:   Report thread summary information rather than function statistics.

-s *KEYS*[,*KEYS*,...], \--sort=*KEYS*[,*KEYS*,...]
:   Sort functions by given KEYS.  Multiple KEYS can be given, separated by comma (,).  Possible keys are `total` (time), `self` (time), `call`, `avg`, `min`, `max`.  Note that the first 3 keys should be used when neither of `--avg-total` nor `--avg-self` is used.  Likewise, the last 3 keys should be used when either of those options is used.

\--avg-total
:   Show average, min, max of each function's total time.

\--avg-self
:   Show average, min, max of each function's self time.

\--diff=*DATA*
:   Report differences between the input trace data and the given DATA.

\--sort-column=*IDX*
:   When `--diff` is used, 3 columns will be shown: total time, self time and call count.  This option selects the index of the column to be used as a sort key.  Index 0 is for original data given by the `--data` option, index 1 is for data given by the `--diff` option, and index 2 is for (percentage) differences between the two data.

-k, \--kernel
:   Show kernel functions as well as user functions.  Only kernel functions called inside user functions will be shown.

--kernel-full
:   Show all kernel functions, including those called outside of user functions.

\--kernel-only
:   Show kernel functions only without user functions.  Implies `--kernel`.

-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions only.  This option can be used more than once.  See `uftrace-replay`(1) for an explanation of filters.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions (or the functions called underneath them).  This option can be used more than once.  See `uftrace-replay`(1) for an explanation of filters.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See `uftrace-replay`(1) for an explanation of triggers.

-t *TIME*, \--time-filter=*TIME*
:   Do not account functions which run under the time threshold.  If some functions explicitly have the 'trace' trigger applied, those are always accounted regardless of execution time.

\--tid=*TID*[,*TID*,...]
:   Only print functions called by the given threads.  To see the list of threads in the data file, you can use `uftrace report --threads` or `uftrace info`.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.


EXAMPLE
=======
This command shows information like the following:

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
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1)
