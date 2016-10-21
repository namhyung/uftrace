% UFTRACE-GRAPH(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Jun, 2016

NAME
====
uftrace-graph - Show function call graph


SYNOPSIS
========
uftrace graph [*options*] [<function>]


DESCRIPTION
===========
This command shows a function call graph for the given function in a uftrace record datafile.  If the function name is omitted, `main` is used by default.  The function call graph contains backtrace and calling functions.  Each function in the output is annotated with a hit count and the total time spent running that function.


OPTIONS
=======
-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions only.  This option can be used more than once.  See `uftrace-replay`(1) for an explanation of filters.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions (or the functions called underneath them).  This option can be used more than once.  See `uftrace-replay`(1) for an explanation of filters.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See `uftrace-replay`(1) for an explanation of triggers.

-t *TIME*, \--time-filter=*TIME*
:   Do not show functions which run under the time threshold.  If some functions explicitly have the 'trace' trigger applied, those are always traced regardless of execution time.

\--tid=*TID*[,*TID*,...]
:   Only print functions called by the given threads.  To see the list of threads in the data file, you can use `uftrace report --threads` or `uftrace info`.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

--max-stack=*DEPTH*
:   Allocate internal graph structure up to *DEPTH*.

-k, \--kernel
:   Trace kernel functions as well as user functions.

\--kernel-full
:   Show all kernel functions called outside of user functions.  This option is the inverse of `--kernel-skip-out`.  Implies `--kernel`.

\--kernel-skip-out
:   Do not show kernel functions called outside of user functions.  This option is deprecated and set to true by default.

\--kernel-only
:   Show kernel functions only without user functions.  Implies `--kernel`.


EXAMPLES
========
This command show data like below:

    $ uftrace record loop

    $ uftrace replay
    # DURATION    TID     FUNCTION
                [24447] | main() {
                [24447] |   foo() {
       8.134 us [24447] |     loop();
       7.296 us [24447] |     loop();
       7.234 us [24447] |     loop();
      24.324 us [24447] |   } /* foo */
                [24447] |   foo() {
       7.234 us [24447] |     loop();
       7.231 us [24447] |     loop();
       7.231 us [24447] |     loop();
      22.302 us [24447] |   } /* foo */
                [24447] |   bar() {
      10.100 ms [24447] |     usleep();
      10.138 ms [24447] |   } /* bar */
      10.293 ms [24447] | } /* main */

Running the `graph` command on the `main` function shows called functions like below:

    $ uftrace graph main
    #
    # function graph for 'main'
    #
    
    backtrace
    ================================
     backtrace #0: hit 1, time  10.293 ms
       [0] main (0x4004f0)
    
    calling functions
    ================================
      10.293 ms : (1) main
      46.626 us :  +-(2) foo
      44.360 us :  | (6) loop
                :  | 
      10.138 ms :  +-(1) bar
      10.100 ms :    (1) usleep

The left side shows total time running the function on the right side.  The number in parentheses before the function name is the invocation count.  As you can see, `main` was called once and ran around 10 msec.  It called `foo` twice and then `foo` called `loop` 6 times in total.  The time is the sum of all execution time of the function.

It can also be seen that `main` called `bar` once and that `bar` then called `usleep` once.  To avoid too deep nesting level, it shows calls that have only a single call path at the same level.  So `usleep` is not called from `main` directly.

Running graph command on a leaf function looks like below.

    $ uftrace graph loop
    #
    # function graph for 'loop'
    #
    
    backtrace
    ================================
     backtrace #0: hit 6, time  44.360 us
       [0] main (0x4004b0)
       [1] foo (0x400622)
       [2] loop (0x400f5f6)
    
    calling functions
    ================================
      44.360 us : (6) loop

The backtrace shows that loop is called from `foo` and that `foo` is called from `main`.  Since `loop` is a leaf function, it didn't call any other function.  In this case, `loop` was called only from a single path so backtrace #0 is hit 6 times.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1)
