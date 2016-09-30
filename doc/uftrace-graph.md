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
This command shows function call graph of the given function.  If the function name is omitted, "main" is used by default.  The function call graph contains backtrace and calling functions.  Each data will contain hit count and total time.


OPTIONS
=======
-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions only.  This option can be used more than once.  See `uftrace-replay` for filters.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions (and their children).  This option can be used more than once.  See `uftrace-replay` for filters.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See `uftrace-replay` for triggers.

\--tid=*TID*[,*TID*,...]
:   Only print functions from given threads.  To see the list of threads in the data file, you can use `uftrace-report --threads` or `uftrace-info` command.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

--max-stack=*DEPTH*
:   Allocate internal graph structure up to *DEPTH*.


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

Running graph command on 'main' function show called functions like below.

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

The left side shows total time running the function on the right side.  The number in parenthesis before function name is the invocation count.  As you can see 'main' function was called once and ran around 10 msec.  It called 'foo' twice and then the 'foo' called 'loop' 6 times in total.  The time is the sum of all execution time of the function.

Also 'main' called 'bar' once and then the 'bar' called 'usleep' once.  To avoid too deep nesting level, it shows calls that have only single call path at the same level.  So 'usleep' is not called from 'main' directly.

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

The backtrace shows it's called from 'foo' and 'foo' is called from 'main'.  Since the 'loop' is a leaf function, it didn't call any other function.  In this case, 'loop' was called only from a single path so the backtrace #0 hits 6 times.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1)
