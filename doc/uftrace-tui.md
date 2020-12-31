% UFTRACE-TUI(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Jun, 2018

NAME
====
uftrace-tui - (Interactive) Text-based User Interface


SYNOPSIS
========
uftrace tui [*options*]


DESCRIPTION
===========
This command starts an interactive window on a terminal which can show same
output of other commands like graph, report and info.  Users can navigate the
result easily with key presses.  The command line options are used to limit
the initial data loading.


TUI OPTIONS
===========
-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: total, self and addr.
    Multiple fields can be set by using comma.  Special field of 'none' can be
    used (solely) to hide all fields.  Default is 'total'.
    See `uftrace-graph`(1) for an explanation of fields.


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


OUTLINE
=======
If there's only one session (the usual case) it'll start with the graph mode to
show a full (function) call graph of the session.  Users can change to different
mode by pressing some keys.  The `h` key always is available for help.

The current line (marked with '>' below) is displayed with inverted color and
arrow keys are used to move the cursor to a different location.

     TOTAL TIME : FUNCTION
    >  7.548 us : (1) t-abc
       1.811 us :  ├─(1) __monstartup
                :  │
       1.266 us :  ├─(1) __cxa_atexit
                :  │
       4.471 us :  └─(1) main
       3.743 us :    (1) a
       3.194 us :    (1) b
       2.454 us :    (1) c
       1.000 us :    (1) getpid
     
     uftrace graph: session 2a22812ebbd06f40 (/tmp/uftrace/tests/t-abc)

If there're more than one session, it'll start with session selection mode.
The graph mode is separated for each session but report mode is merged for the
whole sessions.

     Key uftrace command
    > G  call Graph for session #1: t-forkexec
         call Graph for session #2: t-abc
      R  Report functions
      I  uftrace Info
      h  Help message
      q  quit
     
     session a27acff69aec5c9c:  exe image: /tmp/uftrace/tests/t-forkexec


KEYS
====
Following keys can be used in the TUI window:

 * `Up`, `Down`:          Move cursor up/down
 * `PageUp`, `PageDown`:  Move page up/down
 * `Home`, `End`:         Move to the first/last entry
 * `Enter`:               Fold/unfold graph or Select session
 * `G`:                   Show full graph of the current session
 * `g`:                   Show backtrace and call graph of the current function
 * `R`:                   Show uftrace report
 * `r`:                   Show uftrace report of the current function
 * `s`:                   Sort by the next column (in report mode)
 * `I`:                   Show uftrace info
 * `S`:                   Show session list
 * `O`:                   Open editor for current function
 * `c`/`e`:               Collapse/Expand direct children graph node
 * `C`/`E`:               Collapse/Expand all descendant graph node
 * `n`/`p`:               Move to next/prev sibling (in graph mode)
 * `u`:                   Move up to parent (in graph mode)
 * `l`:                   Move to the longest executed child (in graph mode)
 * `j`/`k`:               Move cursor up/down (like vi)
 * `z`:                   Set current line to the center of screen
 * `/`:                   Start search
 * `<`/`P`:               Search previous match
 * `>`/`N`:               Search next match
 * `v`:                   Show debug message
 * `h`/`?`:               Show help window
 * `q`:                   Quit


SEE ALSO
========
`uftrace`(1), `uftrace-graph`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-replay`(1)
