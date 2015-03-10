% FTRACE-REPORT(1) Ftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
ftrace-report - Print statistics and summary for trace data

SYNOPSIS
========
ftrace report [*options*]

DESCRIPTION
===========
This command collects trace data from a given data file and prints statistics and summary information.  It shows function statistics by default, but can show threads statistics with `--threads` option.

OPTIONS
=======
-f *FILE*, \--file=*FILE*
:   Use this filename for trace data.  Default is `ftrace.dir`.

\--threads
:   Report thread summary information rather than function statistics.

EXAMPLE
=======
This command shows information like below:

    $ ftrace record abc
    $ ftrace report
      Function                                  Total time   Self time  Nr. called
      ========================================  ==========  ==========  ==========
      __cxa_atexit                              150.829 us  150.829 us           1
      main                                       27.289 us    1.243 us           1
      a                                          26.046 us    0.939 us           1
      b                                          25.107 us    0.934 us           1
      c                                          24.173 us    1.715 us           1
      getpid                                     22.458 us   22.458 us           1

    $ ./ftrace report --threads
        TID  Start function                              Run time   Nr. funcs
      =====  ========================================  ==========  ==========
      21959  main                                      178.118 us           6
	
SEE ALSO
========
`ftrace`(1), `ftrace-record`(1)
