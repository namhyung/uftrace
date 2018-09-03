% UFTRACE-GRAPH(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Jun, 2016

NAME
====
uftrace-graph - Show function call graph


SYNOPSIS
========
uftrace graph [*options*] [*FUNCTION*]


DESCRIPTION
===========
This command shows a function call graph for the binary or the given function in a uftrace record datafile.  If the function name is omitted, whole function call graph will be shonw.  If user gives a function name it will show backtrace and calling functions.  Each function in the output is annotated with a hit count and the total time spent running that function.


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
:   Only print functions called by the given threads.  To see the list of threads in the data file, you can use `uftrace report --threads` or `uftrace info`.  This option can also be used more than once.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: total, self and addr.  Multiple fields can be set by using comma.  Special field of 'none' can be used (solely) to hide all fields.  Default is 'total'.  See *FIELDS*.

-r *RANGE*, \--time-range=*RANGE*
:   Only show functions executed within the time RANGE.  The RANGE can be \<start\>~\<stop\> (separated by "~") and one of \<start\> and \<stop\> can be omitted.  The \<start\> and \<stop\> are timestamp or elapsed time if they have \<time_unit\> postfix, for example '100us'.  The timestamp or elapsed time can be shown with `-f time` or `-f elapsed` option respectively in `uftrace replay`(1).

--max-stack=*DEPTH*
:   Allocate internal graph structure up to *DEPTH*.

-k, \--kernel
:   Trace kernel functions as well as user functions.  Note that this option is set by default and always shows kernel functions if exist.

\--kernel-full
:   Show all kernel functions called outside of user functions.  This option is the inverse of `--kernel-skip-out`.

\--kernel-skip-out
:   Do not show kernel functions called outside of user functions.  This option is deprecated and set to true by default.

\--kernel-only
:   Show kernel functions only without user functions.

\--event-full
:   Show all (user) events outside of user functions.

\--no-event
:   Do not show any events.

\--demangle=*TYPE*
:   Use demangled C++ symbol names for filters, triggers, arguments and/or return values.  Possible values are "full", "simple" and "no".  Default is "simple" which ignores function arguments and template parameters.

--match=*TYPE*
:   Use pattern match using TYPE.  Possible types are `regex` and `glob`.  Default is `regex`.


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

Running the `graph` command shows function call graph like below:

    $ uftrace graph
    # Function Call Graph for 'loop' (session: 073f1e84aa8b09d3)
    ========== FUNCTION CALL GRAPH ==========
      10.293 ms : (1) loop
      10.293 ms : (1) main
      46.626 us :  +-(2) foo
      44.360 us :  | (6) loop
                :  | 
      10.138 ms :  +-(1) bar
      10.100 ms :    (1) usleep

The topmost node is not for function but for the executable.
The left side shows total time running the function on the right side.  The number in parentheses before the function name is the invocation count.  As you can see, `main` was called once and ran around 10 msec.  It called `foo` twice and then `foo` called `loop` 6 times in total.  The time is the sum of all execution time of the function.

It can also be seen that `main` called `bar` once and that `bar` then called `usleep` once.  To avoid too deep nesting level, it shows calls that have only a single call path at the same level.  So `usleep` is not called from `main` directly.

Running the `graph` command on the `main` function shows called functions and backtrace like below:

    $ uftrace graph main
    # Function Call Graph for 'main' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 1, time  10.293 ms
       [0] main (0x4004f0)
    
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME   FUNCTION
       10.293 ms : (1) main
       46.626 us :  +-(2) foo
       44.360 us :  | (6) loop
                 :  | 
       10.138 ms :  +-(1) bar
       10.100 ms :    (1) usleep

Note that the 'main' is the top-level function so it has no backtrace above itself.
Running graph command on a leaf function looks like below.

    $ uftrace graph loop
    # Function Call Graph for 'loop' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 6, time  44.360 us
       [0] main (0x4004b0)
       [1] foo (0x400622)
       [2] loop (0x400f5f6)
    
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME   FUNCTION
       44.360 us : (6) loop

The backtrace shows that loop is called from `foo` and that `foo` is called from `main`.  Since `loop` is a leaf function, it didn't call any other function.  In this case, `loop` was called only from a single path so backtrace #0 is hit 6 times.


FIELDS
======
The uftrace allows for user to customize the graph output with some of fields.  Here the field means info on the left side of the colon (:) character.  By default it uses time only, but you can use other fields in any order like:

    $ uftrace record tests/t-abc
    $ uftrace graph -f total,self,addr
    # Function Call Graph for 't-sort' (session: b007f4b7cf792878)
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME  SELF TIME      ADDRESS     FUNCTION
       10.145 ms              561f652cd610 : (1) t-sort
       10.145 ms   39.890 us  561f652cd610 : (1) main
       16.773 us    0.734 us  561f652cd7ce :  +-(2) foo
       16.039 us   16.039 us  561f652cd7a0 :  | (6) loop
                                           :  |
       10.088 ms   14.740 us  561f652cd802 :  +-(1) bar
       10.073 ms   10.073 ms  561f652cd608 :    (1) usleep

Each field has following meaning:

 * total: function execution time in total
 * self : function execution time excluding its children's
 * addr : address of the function

The default value is 'total'.  If given field name starts with "+", then it'll be appended to the default fields.  So "-f +addr" is as same as "-f total,addr".  And it also accepts a special field name of 'none' which disables the field display and shows function output only.

    $ uftrace graph -f none
    # Function Call Graph for 't-sort' (session: b007f4b7cf792878)
    ========== FUNCTION CALL GRAPH ==========
    (1) t-sort
    (1) main
     +-(2) foo
     | (6) loop
     |
     +-(1) bar
       (1) usleep

This output can be useful when comparing two different call graph outputs using diff tool.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-tui`(1)
