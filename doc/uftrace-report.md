% UFTRACE-REPORT(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace-report - Print statistics and summary for trace data


SYNOPSIS
========
uftrace report [*options*]


DESCRIPTION
===========
This command collects trace data from a given data file and prints statistics
and summary information.  It shows function statistics by default, but can show
task statistics with the `--task` option and show differences between traces
with the `--diff` option.


REPORT OPTIONS
==============
-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: `total`, `total-avg`,
    `total-min`, `total-max`, `self`, `self-avg`, `self-min`, `self-max` and
    `call`.  Multiple fields can be set by using comma.  Special field of
    'none' can be used (solely) to hide all fields.
    Default is 'total,self,call'.  See *FIELDS*.

-s *KEYS*[,*KEYS*,...], \--sort=*KEYS*[,*KEYS*,...]
:   Sort functions by given KEYS.  Multiple KEYS can be given, separated by
    comma (,).  Possible keys are `total` (time), `total-avg`, `total-min`,
    `total-max`, `self` (time), `self-avg`, `self-min`, `self-max`, `call`
    and `func`.
    Note that the first 3 keys should be used when
    neither of `--avg-total` nor `--avg-self` is used.  Likewise, the last 3
    keys should be used when either of those options is used.

\--avg-total
:   Show average, min, max of each function's total time.

\--avg-self
:   Show average, min, max of each function's self time.

\--task
:   Report task summary information rather than function statistics.
    Customize field in the output with -f option. Possible values are: `total`,
    `self`, `func` and `tid`.  Multiple fields can be set by using comma.
    Special field of 'none' can be used (solely) to hide all fields.
    Default is 'total,self,func,tid'.  See *TASK FIELDS*.

\--diff=*DATA*
:   Report differences between the input trace data and the given DATA.

\--diff-policy=*POLICY*
:   Apply custom diff policy.  Available values are: "abs", "no-abs", "percent",
    "no-percent", "compact" and "full".  The "abs" is to sort diff result using
    absolute value so positive and negative entries can be shown together while
    "no-abs" will show positive entries first and then negative ones.  The
    "percent" is to show diff in percentage while "no-percent" is to show the
    values.  The "full" is to show all three columns of baseline, new data and
    difference while "compact" only shows the difference.  The default is "abs",
    "compact" and "no-percent".

\--sort-column=*IDX*
:   When `--diff` is used with "full" policy, 3 columns will be shown for each
    total time, self time and call count.  This option selects the index of the
    column to be used as a sort key.  Index 0 is for original data given by the
    `--data` option, index 1 is for data given by the `--diff` option, and index
    2 is for (percentage) differences between the two data.

\--srcline
:   Show source location of each function if available.


COMMON OPTIONS
==============
-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions and their children functions.
    This option can be used more than once.
    See `uftrace-replay`(1) for an explanation of filters.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions and their children functions.
    This option can be used more than once.
    See `uftrace-replay`(1) for an explanation of filters.

-H *FUNC*, \--hide=*FUNC*
:   Set filter not to trace selected functions.
    It doesn't affect their subtrees, but hides only the given functions.
    This option can be used more than once.
    See `uftrace-replay`(1) for an explanation of filters.

-C *FUNC*, \--caller-filter=*FUNC*
:   Set filter to trace callers of selected functions only.
    This option can be used more than once.
    See `uftrace-replay`(1) for an explanation of filters.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.
    See `uftrace-replay`(1) for an explanation of triggers.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

-t *TIME*, \--time-filter=*TIME*
:   Do not account functions which run under the time threshold.  If some
    functions explicitly have the 'trace' trigger applied, those are always
    accounted regardless of execution time.

\--no-libcall
:   Do not show library calls.

\--no-event
:   Do not show any events.

\--match=*TYPE*
:   Use pattern match using TYPE.  Possible types are `regex` and `glob`.
    Default is `regex`.


COMMON ANALYSIS OPTIONS
=======================
\--kernel-full
:   Show all kernel functions, including those called outside of user functions.

\--kernel-only
:   Show kernel functions only without user functions.

\--event-full
:   Show all (user) events outside of user functions.

\--tid=*TID*[,*TID*,...]
:   Only print functions called by the given tasks.  To see the list of
    tasks in the data file, you can use `uftrace report --task` or
    `uftrace info`.  This option can also be used more than once.

\--demangle=*TYPE*
:   Use demangled C++ symbol names for filters, triggers, arguments and/or
    return values.  Possible values are "full", "simple" and "no".  Default
    is "simple" which ignores function arguments and template parameters.

-r *RANGE*, \--time-range=*RANGE*
:   Only show functions executed within the time RANGE.  The RANGE can be
    \<start\>~\<stop\> (separated by "~") and one of \<start\> and \<stop\> can
    be omitted.  The \<start\> and \<stop\> are timestamp or elapsed time if
    they have \<time_unit\> postfix, for example '100us'.  The timestamp or
    elapsed time can be shown with `-f time` or `-f elapsed` option respectively
    in `uftrace replay`(1).


EXAMPLE
=======
This command shows information like the following:

    $ uftrace record abc
    $ uftrace report
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
      150.829 us  150.829 us           1  __cxa_atexit
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b
       24.173 us    1.715 us           1  c
       22.458 us   22.458 us           1  getpid

    $ uftrace report -s call,self
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
      150.829 us  150.829 us           1  __cxa_atexit
       22.458 us   22.458 us           1  getpid
       24.173 us    1.715 us           1  c
       27.289 us    1.243 us           1  main
       26.046 us    0.939 us           1  a
       25.107 us    0.934 us           1  b

    $ uftrace report --avg-self
        Avg self    Min self    Max self  Function
      ==========  ==========  ==========  ====================
      150.829 us  150.829 us  150.829 us  __cxa_atexit
       22.458 us   22.458 us   22.458 us  getpid
        1.715 us    1.715 us    1.715 us  c
        1.243 us    1.243 us    1.243 us  main
        0.939 us    0.939 us    0.939 us  a
        0.934 us    0.934 us    0.934 us  b

    $ uftrace report --task
      Total time   Self time   Num funcs     TID  Task name
      ==========  ==========  ==========  ======  ================
       22.178 us   22.178 us           7   29955  t-abc

    $ uftrace record --srcline abc
    $ uftrace report --srcline
      Total time   Self time       Calls  Function [Source]
      ==========  ==========  ==========  ====================
       17.508 us    2.199 us           1  main [./tests/s-abc.c:26]
       15.309 us    2.384 us           1  a [./tests/s-abc.c:11]
       12.925 us    2.633 us           1  b [./tests/s-abc.c:16]
       10.292 us    5.159 us           1  c [./tests/s-abc.c:21]
        5.133 us    5.133 us           1  getpid
        3.437 us    3.437 us           1  __monstartup
        1.959 us    1.959 us           1  __cxa_atexit

To see a difference between two data:

    $ uftrace record abc

    $ uftrace report --diff uftrace.data.old
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
       -0.301 us   -0.038 us          +0  main
       -0.263 us   -0.070 us          +0  a
       -0.193 us   -0.042 us          +0  b
       -0.151 us   -0.090 us          +0  c
       -0.131 us   -0.131 us          +0  __cxa_atexit
       -0.061 us   -0.061 us          +0  getpid

The above example shows difference sorted by absolute value of total time.
The following changes it to use (non-absolute) value of self time.

    $ uftrace report --diff uftrace.data.old -s self --diff-policy no-abs
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================
       -0.301 us   -0.038 us          +0  main
       -0.193 us   -0.042 us          +0  b
       -0.061 us   -0.061 us          +0  getpid
       -0.263 us   -0.070 us          +0  a
       -0.151 us   -0.090 us          +0  c
       -0.131 us   -0.131 us          +0  __cxa_atexit

By using "full" policy, user can see raw data as well like below.
Also it's possible to sort by different column (for raw data).
The example below will sort output by total time of the base data.

    $ uftrace report --diff uftrace.data.old --sort-column 0 --diff-policy full,percent
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record abc )
    #  [1] diff: uftrace.data.old   (from uftrace record abc )
    #
                     Total time (diff)                   Self time (diff)                  Nr. called (diff)   Function
      ================================   ================================   ================================   ====================
        2.812 us    2.511 us   -10.70%     0.403 us    0.365 us    -9.43%            1          1         +0   main
        2.409 us    2.146 us   -10.92%     0.342 us    0.272 us   -20.47%            1          1         +0   a
        2.067 us    1.874 us    -9.34%     0.410 us    0.368 us   -10.24%            1          1         +0   b
        1.657 us    1.506 us    -9.11%     0.890 us    0.800 us   -10.11%            1          1         +0   c
        0.920 us    0.789 us   -14.24%     0.920 us    0.789 us   -14.24%            1          1         +0   __cxa_atexit
        0.767 us    0.706 us    -7.95%     0.767 us    0.706 us    -7.95%            1          1         +0   getpid

FIELDS
======
The uftrace allows for user to customize the report output with a couple of fields.
By default it uses total, self and call fields, but you can use other fields
in any order like:

    $ uftrace report -f total,total-max,self-min,call
    Total time   Total max    Self min       Calls  Function
    ==========  ==========  ==========  ==========  ====================
     97.234 us   36.033 us    1.073 us           3  lib_a
     50.552 us   26.690 us    2.828 us           2  lib_b
     46.806 us   46.806 us    3.290 us           1  main
     43.516 us   43.516 us    7.483 us           1  foo
     32.010 us   20.847 us    9.684 us           2  lib_c

Each field can be used as sort key:

    $ uftrace report -f total,total-max,self-min,call -s call
    Total time   Total max    Self min       Calls  Function
    ==========  ==========  ==========  ==========  ====================
     97.234 us   36.033 us    1.073 us           3  lib_a
     50.552 us   26.690 us    2.828 us           2  lib_b
     32.010 us   20.847 us    9.684 us           2  lib_c
     43.516 us   43.516 us    7.483 us           1  foo
     46.806 us   46.806 us    3.290 us           1  main

    $ uftrace report -f total,total-max,self-min,total-min,call -s self-min,total-min
    Total time   Total max    Self min   Total min       Calls  Function
    ==========  ==========  ==========  ==========  ==========  ====================
     32.010 us   20.847 us    9.684 us   11.163 us           2  lib_c
     43.516 us   43.516 us    7.483 us   43.516 us           1  foo
     46.806 us   46.806 us    3.290 us   46.806 us           1  main
     50.552 us   26.690 us    2.828 us   23.862 us           2  lib_b
     97.234 us   36.033 us    1.073 us   27.763 us           3  lib_a

Each field can be used with --diff option:

    $ uftrace report --diff uftrace.data.old -f total,total-min
    #
    # uftrace diff
    #  [0] base: uftrace.data       (from uftrace record test/t-lib)
    #  [1] diff: uftrace.data.old   (from uftrace record test/t-lib)
    #
     Total time     Total min   Function
    ===========   ===========   ====================
     +34.560 us     +9.884 us   lib_a
     +18.086 us     +8.517 us   lib_b
     +16.887 us    +16.887 us   main
     +15.479 us    +15.479 us   foo
     +10.600 us     +3.127 us   lib_c

    $ uftrace report --diff uftrace.data.old -f total,total-min,self-avg --diff-policy full
    #
    # uftrace diff
    #  [0] base: uftrace.data           (from uftrace record --srcline test/t-lib)
    #  [1] diff: uftrace.data.old	(from uftrace record --srcline test/t-lib)
    #
                      Total time (diff)                      Total min (diff)                       Self avg (diff)   Function
    ===================================   ===================================   ===================================   ====================
     14.616 us   13.796 us    +0.820 us     4.146 us    3.823 us    +0.323 us     0.443 us    0.459 us    -0.016 us   lib_a
      6.529 us    5.957 us    +0.572 us     6.529 us    5.957 us    +0.572 us     0.436 us    0.356 us    +0.080 us   main
      7.700 us    7.173 us    +0.527 us     3.677 us    3.426 us    +0.251 us     0.365 us    0.363 us    +0.002 us   lib_b
      6.093 us    5.601 us    +0.492 us     6.093 us    5.601 us    +0.492 us     0.741 us    0.476 us    +0.265 us   foo
      5.638 us    5.208 us    +0.430 us     2.346 us    2.187 us    +0.159 us     1.646 us    1.510 us    +0.136 us   lib_c

Each field has following meaning:

 * total: total time of each function.
 * total-avg: average of total time of each function.
 * total-min: min of total time of each function.
 * total-max: max of total time of each function.
 * self: self time of each function.
 * self-avg: average of self time of each function.
 * self-min: min of self time of each function.
 * self-max: max of self time of each function.
 * call: called count of each function.

The default value is 'total,self,call'.  If given field name starts with "+",
then it'll be appended to the default fields.  So "-f +total-avg" is as same as
"-f total,self,call,total-avg".  And it also accepts a special field name of
'none' which disables the field display and shows function output only.

TASK FIELDS
======
 * total: total time of each task.
 * self: self time of each task.
 * func: number of functions in the task.
 * tid: task ID.

The default value is 'total,self,func,tid'. See *FIELDS* for field usage.

SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-tui`(1)
