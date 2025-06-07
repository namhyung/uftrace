% UFTRACE-GRAPH(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace-graph - Show function call graph


SYNOPSIS
========
uftrace graph [*options*] [*FUNCTION*]


DESCRIPTION
===========
This command shows a function call graph for the binary or the given function
in a uftrace record datafile.  If the function name is omitted, whole function
call graph will be shown.  If a user provides a function name, it will show backtrace
and calling functions.  Each function in the output is annotated with a hit
count and the total time spent running that function.


GRAPH OPTIONS
=============
-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: total, self, addr, total-avg,
    total-max, total-min, self-avg, self-max, and self-min.
    Multiple fields can be set by using comma.  Special field of 'none' can be
    used (solely) to hide all fields.  Default is 'total'.  See *FIELDS*.

\--task
:   Print task graph instead of normal function graph.  Each node in the
    output shows a process or thread(printed in green color).

\--srcline
:   Show source location of each function if available.

\--format=*TYPE*
:   Show format style output. Currently, normal and html styles are supported.


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
:   Do not show functions which run under the time threshold.  If some functions
    explicitly have the 'trace' trigger applied, those are always traced
    regardless of execution time.

-Z *SIZE*, \--size-filter=*SIZE*
:   Do not show functions smaller than SIZE bytes.

-L *LOCATION*, \--loc-filter=*LOCATION*
:   Set filter to trace selected source locations.
    This option can be used more than once.

\--no-libcall
:   Do not show library calls.

\--no-event
:   Do not show any events.  Implies `--no-sched`.

\--no-sched
:   Do not show schedule events.

\--no-sched-preempt
:   Do not show preempt schedule events
    but show regular(sleeping) schedule events.

\--match=*TYPE*
:   Use pattern match using TYPE.  Possible types are `regex` and `glob`.
    Default is `regex`.

\--with-syms=*DIR*
:   Read symbol data from the .sym files in *DIR* directory instead of the
    binary.  This can be useful to deal with stripped binaries.  The file name
    of the main binary should be the same when saved and used.


COMMON ANALYSIS OPTIONS
=======================
-H *FUNC*, \--hide=*FUNC*
:   Set filter not to trace selected functions.
    It doesn't affect their subtrees, but hides only the given functions.
    This option can be used more than once.
    See `uftrace-replay`(1) for an explanation of filters.

\--kernel-full
:   Show all kernel functions called outside of user functions.

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
    return values.  Possible values are "full", "simple" and "no".  Default is
    "simple" which ignores function arguments and template parameters.

-r *RANGE*, \--time-range=*RANGE*
:   Only show functions executed within the time RANGE.  The RANGE can be
    \<start\>~\<stop\> (separated by "~") and one of \<start\> and \<stop\> can
    be omitted.  The \<start\> and \<stop\> are timestamp or elapsed time if
    they have \<time_unit\> postfix, for example '100us'.  The timestamp or
    elapsed time can be shown with `-f time` or `-f elapsed` option respectively
    in `uftrace replay`(1).


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

The graph root is not a function, but the executing process itself.
The left side shows total time running the function on the right side.
The number in parentheses before the function name is the invocation count.
As you can see, `main` was called once and ran for 10 msec.  It called
`foo` twice and then `foo` called `loop` 6 times in total.  The printed time is the
total execution time for all function invocations.

It can also be seen that `main` called `bar` once and that `bar` then called
`usleep` once.  To minimize nesting, the output shows calls at the same level if
only a single call path exists.  Since the nodes `usleep` and `main` are not
directly connected, `usleep` is not called from `main` directly.

Running the `graph` command on the `main` function shows called functions and
backtrace like below:

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

Note that the 'main' is the top-level function so it has no backtrace above
itself.  Running the graph command on a leaf function looks like below.

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

The backtrace shows that loop is called from `foo` and that `foo` is called
from `main`.  Since `loop` is a leaf function, it didn't call any other
function.  In this case, `loop` was called only from a single path so
backtrace #0 is hit 6 times.

While graph command shows function-level call graph, --task option makes the
output in task-level graph which shows how processes and threads are created.
The term here `task` includes process and thread.

For example, the task graph of GCC compiler can be shown as follows:

    $ uftrace record --force /usr/bin/gcc hello.c

    $ uftrace graph --task
    ========== TASK GRAPH ==========
    # TOTAL TIME   SELF TIME     TID     TASK NAME
      159.854 ms    4.440 ms  [ 82723] : gcc
                                       :  |
       90.951 ms   90.951 ms  [ 82734] :  +----cc1
                                       :  |
       17.150 ms   17.150 ms  [ 82735] :  +----as
                                       :  |
       45.183 ms    6.076 ms  [ 82736] :  +----collect2
                                       :        |
       38.880 ms   38.880 ms  [ 82737] :        +----ld

The above output shows `gcc` created `cc1`, `as`, and `collect2` processes then
`collect2` created `ld` process.

`TOTAL TIME` is the lifetime of the task from its creation to termination, and
`SELF TIME` is also lifetime, but it excludes internal idle time.  `TID` is the
thread id of the task.

The following shows task graph of uftrace recording itself.  It shows uftrace
created `t-abc` process, and also created many threads whose names are all
`WriterThread`.

    $ uftrace record -P. ./uftrace record -d uftrace.data.abc t-abc

    $ uftrace graph --task
    ========== TASK GRAPH ==========
    # TOTAL TIME   SELF TIME     TID     TASK NAME
      404.929 ms  321.692 ms  [  4230] : uftrace
                                       :  |
      278.662 us  278.662 us  [  4241] :  +----t-abc
                                       :  |
       33.754 ms    4.061 ms  [  4242] :  +-WriterThread
       27.415 ms  120.992 us  [  4244] :  +-WriterThread
       27.212 ms    8.119 ms  [  4245] :  +-WriterThread
       26.754 ms    6.616 ms  [  4248] :  +-WriterThread
       26.859 ms    8.154 ms  [  4247] :  +-WriterThread
       26.509 ms    1.645 ms  [  4243] :  +-WriterThread
       25.320 ms   57.350 us  [  4246] :  +-WriterThread
       24.757 ms    4.391 ms  [  4249] :  +-WriterThread
       26.040 ms    3.707 ms  [  4250] :  +-WriterThread
       24.004 ms    3.999 ms  [  4251] :  +-WriterThread

Please note that the indentation depth of thread is different from process.

Running the `graph` command with `--srcline` option shows source location
in call graph like below:

    $ uftrace record --srcline t-abc
    $ uftrace graph --srcline
    # Function Call Graph for 't-abc' (session: 60195bac953d8736)
    ========== FUNCTION CALL GRAPH ==========
    # TOTAL TIME   FUNCTION [SOURCE]
      8.909 us : (1) t-abc
      1.260 us :  +-(1) __monstartup
               :  |
      0.179 us :  +-(1) __cxa_atexit
               :  |
      7.470 us :  +-(1) main [tests/s-abc.c:26]
      5.522 us :    (1) a [tests/s-abc.c:11]
      4.912 us :    (1) b [tests/s-abc.c:16]
      4.176 us :    (1) c [tests/s-abc.c:21]
      0.794 us :    (1) getpid

FIELDS
======
The uftrace allows for user to customize the graph output with some of fields.
Here the field means info on the left side of the colon (:) character.
By default it uses time only, but you can use other fields in any order like:

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
 * total-avg: average of total time of each function.
 * total-max: max of total time of each function.
 * total-min: min of total time of each function.
 * self : function execution time excluding its children's
 * self-avg: average of self time of each function.
 * self-max: max of self time of each function.
 * self-min: min of self time of each function.
 * addr : address of the function

The default value is 'total'.  If given field name starts with "+", then it'll
be appended to the default fields.  So "-f +addr" is as same as "-f total,addr".
And it also accepts a special field name of 'none' which disables the field
display and shows function output only.

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

This output can be useful when comparing two different call graph outputs using
diff tool.

It also supports field customization for task graph.  The default field is set
to `total,self,tid`, but the field option can also be used as follows:

    $ uftrace graph --task -f tid,self
    ========== TASK GRAPH ==========
    #    TID     SELF TIME   TASK NAME
      [ 82723]    4.440 ms : gcc
                           :  |
      [ 82734]   90.951 ms :  +----cc1
                           :  |
      [ 82735]   17.150 ms :  +----as
                           :  |
      [ 82736]    6.076 ms :  +----collect2
                           :        |
      [ 82737]   38.880 ms :        +----ld

Each field has following meaning:

 * total: total task lifetime from its creation to termination
 * self : task execution time excluding its idle time
 * tid  : task id (obtained by gettid(2))

It also accepts a special field `none`, which hides all the fields on the left.

    $ uftrace graph --task -f none
    ========== TASK GRAPH ==========
    gcc
     |
     +----cc1
     |
     +----as
     |
     +----collect2
           |
           +----ld


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-tui`(1)
