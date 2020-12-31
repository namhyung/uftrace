% UFTRACE-DUMP(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace-dump - Print raw tracing data in the data files


SYNOPSIS
========
uftrace dump [*options*]


DESCRIPTION
===========
This command shows raw tracing data recorded in the data file.  The dump format
can be configured by additional options such as --chrome, --flame-graph,
or --graphviz.


DUMP OPTIONS
============
\--chrome
:   Show JSON style output as used by the Google Chrome tracing facility.

\--flame-graph
:   Show FlameGraph style output viewable by modern web browsers (after
    processing by the FlameGraph tool).

\--graphviz
:   Show DOT style output used by the graphviz toolkit.

\--debug
:   Show hex dump of data as well

\--sample-time=*TIME*
:   Apply sampling time when generating output for --flame-graph.  By default
    it uses the number of calls for each function.  When this option is used it
    simulates sampling by counting execution time at the given unit.  So
    functions which ran less than the sampling time will be removed from the
    output but functions longer than the time will be shown as larger.


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
:   Do not show functions which run under the time threshold.  If some functions
    explicitly have the 'trace' trigger applied, those are always traced
    regardless of execution time.

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
:   Show all kernel functions called outside of user functions.  This option is
    only meaningful when used with \--chrome, \--flame-graph or \--graphviz
    options.

\--kernel-only
:   Dump kernel functions only without user functions.

\--event-full
:   Show all (user) events outside of user functions.  This option is only
    meaningful when used with \--chrome, \--flame-graph or \--graphviz options.

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
This command dumps data like below:

    $ uftrace record abc

    $ uftrace dump
    uftrace file header: magic         = 4674726163652100
    uftrace file header: version       = 4
    uftrace file header: header size   = 40
    uftrace file header: endian        = 1 (little)
    uftrace file header: class         = 2 (64 bit)
    uftrace file header: features      = 0x63 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK)
    uftrace file header: info          = 0x3ff

    reading 23043.dat
    105430.415350255  23043: [entry] __monstartup(4004d0) depth: 0
    105430.415351178  23043: [exit ] __monstartup(4004d0) depth: 0
    105430.415351932  23043: [entry] __cxa_atexit(4004f0) depth: 0
    105430.415352687  23043: [exit ] __cxa_atexit(4004f0) depth: 0
    105430.415353833  23043: [entry] main(400512) depth: 0
    105430.415353992  23043: [entry] a(4006b2) depth: 1
    105430.415354112  23043: [entry] b(4006a0) depth: 2
    105430.415354230  23043: [entry] c(400686) depth: 3
    105430.415354425  23043: [entry] getpid(4004b0) depth: 4
    105430.415355035  23043: [exit ] getpid(4004b0) depth: 4
    105430.415355549  23043: [exit ] c(400686) depth: 3
    105430.415355761  23043: [exit ] b(4006a0) depth: 2
    105430.415355943  23043: [exit ] a(4006b2) depth: 1
    105430.415356109  23043: [exit ] main(400512) depth: 0

    $ uftrace dump --chrome -F main
    {"traceEvents":[
    {"ts":105430415353,"ph":"B","pid":23043,"name":"main"},
    {"ts":105430415353,"ph":"B","pid":23043,"name":"a"},
    {"ts":105430415354,"ph":"B","pid":23043,"name":"b"},
    {"ts":105430415354,"ph":"B","pid":23043,"name":"c"},
    {"ts":105430415354,"ph":"B","pid":23043,"name":"getpid"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"getpid"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"c"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"b"},
    {"ts":105430415355,"ph":"E","pid":23043,"name":"a"},
    {"ts":105430415356,"ph":"E","pid":23043,"name":"main"}
    ], "metadata": {
    "command_line":"uftrace record abc ",
    "recorded_time":"Tue May 24 19:44:54 2016"
    } }

    $ uftrace dump --flame-graph --sample-time 1us
    main 1
    main;a;b;c 1

    $ uftrace dump --graphviz
    \# command_line "uftrace record tests/t-abc"
    digraph "/home/m/git/uftrace/tests/t-abc" {
            \# Attributes
            splines=ortho;
            concentrate=true;
            node [shape="rect",fontsize="7",style="filled"];
            edge [fontsize="7"];
            \# Elements
            main[xlabel = "Calls : 1"]
            main->a[xlabel = "Calls : 1"]
            a->b[xlabel = "Calls : 1"]
            b->c[xlabel = "Calls : 1"]
            c->getpid[xlabel = "Calls : 1"]
    }

SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1)
