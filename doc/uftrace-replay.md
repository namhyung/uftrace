% UFTRACE-REPLAY(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace-replay - Print recorded function trace


SYNOPSIS
========
uftrace replay [*options*]


DESCRIPTION
===========
This command prints trace data recorded using the `uftrace-record`(1) command.
The traced functions are printed like a C program in time order.


REPLAY OPTIONS
==============
-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: duration, tid, addr,
    time, delta, elapsed, task and module.  Multiple fields can be set by using
    comma.  Special field of 'none' can be used (solely) to hide all fields.
    Default is 'duration,tid'.  See *FIELDS*.

\--flat
:   Print flat format rather than C-like format.  This is usually for debugging
    and testing purpose.

\--column-view
:   Show each task in separate column.  This makes easy to distinguish functions
    in different tasks.

\--column-offset=*DEPTH*
:   When `--column-view` option is used, this option specifies the amount of
    offset between each task.  Default is 8.

\--task-newline
:   Interleave a new line when task is changed.  This makes easy to distinguish
    functions in different tasks.

\--no-comment
:   Do not show comments of returned functions.

\--libname
:   Show libname name along with function name.

\--srcline
:   Show source location of each function if available.

\--format=*TYPE*
:   Show format style output. Currently, normal and html styles are supported.

\--no-args
:   Do not show function arguments and return value.


COMMON OPTIONS
==============
-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions and their children functions.
    This option can be used more than once.  See *FILTERS*.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions and their children functions.
    This option can be used more than once.  See *FILTERS*.

-C *FUNC*, \--caller-filter=*FUNC*
:   Set filter to trace callers of selected functions only.
    This option can be used more than once.  See *FILTERS*.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.
    See *TRIGGERS*.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.  See *FILTERS*.

-t *TIME*, \--time-filter=*TIME*
:   Do not show functions which run under the time threshold.  If some functions
    explicitly have the 'trace' trigger applied, those are always traced
    regardless of execution time.  See *FILTERS*.

-Z *SIZE*, \--size-filter=*SIZE*
:   Do not show functions smaller than SIZE bytes.  See *FILTERS*.

-L *LOCATION*, \--loc-filter=*LOCATION*
:   Set filter to trace selected source locations.
    This option can be used more than once.  See *FILTERS*.

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

\--disable
:   DEPRECATED. Use `--trace=off` instead.

\--trace=*STATE*
:   Set uftrace tracing STATE. Possible states are `on` and `off`. Default is
    `on`. This is only meaningful when used with a `trace_on` trigger or with
    the agent

\--with-syms=*DIR*
:   Read symbol data from the .sym files in *DIR* directory instead of the
    binary.  This can be useful to deal with stripped binaries.  The file name
    of the main binary should be the same when saved and used.


COMMON ANALYSIS OPTIONS
=======================
-H *FUNC*, \--hide=*FUNC*
:   Set filter not to trace selected functions.
    It doesn't affect their subtrees, but hides only the given functions.
    This option can be used more than once.  See *FILTERS*.

\--kernel-full
:   Show all kernel functions and events occurred outside of user functions.

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
    elapsed time can be shown with `-f time` or `-f elapsed` option respectively.
    See *FILTERS*.


FILTERS
=======
The uftrace tool supports filtering out uninteresting functions.  When uftrace
is called it receives two types of function filter; an opt-in filter with
`-F`/`--filter` and an opt-out filter with `-N`/`--notrace`.  These filters can
be applied either at record time or replay time.

The first one is an opt-in filter. By default, it doesn't show anything.
But when one of the specified functions is met, printing is started.
When the function returns, printing is stopped again.

For example, consider a simple program which calls `a()`, `b()` and `c()` in turn.

    $ cat abc.c
    void c(void) {
        /* do nothing */
    }

    void b(void) {
        c();
    }

    void a(void) {
        b();
    }

    int main(void) {
        a();
        return 0;
    }

    $ gcc -pg -o abc abc.c

Normally uftrace replay will show all the functions from `main()` to `c()`.

    $ uftrace ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

But when the `-F b` filter option is used, it will not show `main()` or `a()`
but only `b()` and `c()`.  Note that the filter was set on `uftrace replay`,
not at record time.

    $ uftrace record ./abc
    $ uftrace replay -F b
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The second type of filter is opt-out. When used, everything is shown by default,
but printing stops once one of the specified functions is met.  When the given
function returns, printing is started again.

In the above example, you can omit the function `b()` and all calls it makes
with the `-N` option.

    $ uftrace record ./abc
    $ uftrace replay -N b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

The filter condition can be applied to `uftrace replay`.  But it'd work only if
arguments are saved by `uftrace record`.

You can hide the function `b()` only without affecting the calls it makes in its
subtree functions with `-H` option.

    $ uftrace record ./abc
    $ uftrace replay -H b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       3.880 us [ 1234] |     c();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

The above `-H` option is especially useful when hiding std namespace functions
in C++ programs by using `-H ^std::` option setting.

If users only care about specific functions and want to know how they are called,
one can use the caller filter.  It makes the function as leaf and prints the
parent functions to the function.

    $ uftrace record ./abc
    $ uftrace replay -C b
    # DURATION    TID     FUNCTION
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

In the above example, functions not in the calling path were not shown.  Also
the function 'c' - which is a child of the function 'b' - is also hidden.

In addition, you can limit the print nesting level with -D option.

    $ uftrace record ./abc
    $ uftrace replay -D 3
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

In the above example, uftrace only prints functions up to a depth of 3, so leaf
function `c()` was omitted.  Note that the `-D` option also works with `-F`.

Sometimes it's useful to see long-running functions only.  This is good because
there are usually many tiny functions that are not interesting.  The
`-t`/`--time-filter` option implements the time-based filter that only records
functions which run longer than the given threshold.  In the above example, the
user might want to see functions running more than 5 microseconds like below:

    $ uftrace record ./abc
    $ uftrace replay -t 5us
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

You can also see replay output with different time threshold for the same
recorded data.

    $ uftrace replay -t 6us
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

In addition, The `-r` option can show functions executed within the given
time range.  When using this option, you can see TIMESTAMP or ELAPSED fields
as well as DURATION and TID.

    $ uftrace replay -r 502716.387320101~502716.387322389
    #     TIMESTAMP      DURATION    TID     FUNCTION
    502716.387320101   0.289 us [ 6126] |   fgets();
    502716.387320584            [ 6126] |   get_values_from() {
    502716.387320709   0.245 us [ 6126] |     strdup();
    502716.387321172   0.144 us [ 6126] |     strsep();
    502716.387321542   0.223 us [ 6126] |     atoi();
    502716.387321983   0.239 us [ 6126] |     atoi();
    502716.387322389   1.805 us [ 6126] |   } /* get_values_from */

    $ uftrace replay -r 40us~ | head -10
    #  ELAPSED   DURATION    TID     FUNCTION
      40.141 us            [ 6126] |   get_values_from() {
      40.269 us   0.249 us [ 6126] |     strdup();
      40.756 us   0.149 us [ 6126] |     strsep();
      41.119 us   0.235 us [ 6126] |     atoi();
      41.578 us   0.211 us [ 6126] |     atoi();
      41.957 us   1.816 us [ 6126] |   } /* get_values_from */
      42.124 us   0.220 us [ 6126] |   fgets();
      42.529 us            [ 6126] |   get_values_from() {
      42.645 us   0.236 us [ 6126] |     strdup();

In addition, you can set filter to trace selected source locations with `-L` option.
For this option, the `--srcline` option is required when using record command.

    $ uftrace record --srcline t-lib
    $ uftrace replay --srcline -L s-libmain.c
    # DURATION     TID     FUNCTION [SOURCE]
                [  5043] | main() { /* /home/uftrace/tests/s-libmain.c:16 */
       6.998 us [  5043] |   foo(); /* /home/uftrace/tests/s-libmain.c:11 */
       9.393 us [  5043] | } /* main */

You can set filter with the `@hide` suffix not to trace selected source locations.

    $ uftrace replay -L libmain*@hide
    # DURATION     TID     FUNCTION
                [   866] | lib_a() {
                [   866] |   lib_b() {
       1.576 us [   866] |     lib_c();
       2.833 us [   866] |   } /* lib_b */
       3.132 us [   866] | } /* lib_a */

The `-Z`/`--size-filter` option is to filter functions that has small sizes.
It reads symbols size from the .sym files and compare it with the given value.
Note that .sym files might not have the precise value of the function size as
it doesn't save the size value.  It calculate the function size from the
difference of two adjacent function addresses.  So if the compiler aligns the
function start addresses by padding NOP instructions at the end, it could have
slightly bigger size than the actual value.

    $ uftrace record  t-arg
    $ uftrace replay -Z 100
    # DURATION     TID     FUNCTION
                [162500] | main() {
      12.486 us [162500] |   foo();
       0.505 us [162500] |   many();
                [162500] |   pass() {
       0.283 us [162500] |     check();
       1.449 us [162500] |   } /* pass */
      18.478 us [162500] | } /* main */

You can also set triggers on filtered functions.  See *TRIGGERS* section below
for details.


TRIGGERS
========
The uftrace tool supports triggering actions on selected function calls with or
without filters.  Currently supported triggers are `depth`, `backtrace`,
`trace_on` and `trace_off`.  The BNF for trigger specifications is like below:

    <trigger>    :=  <symbol> "@" <actions>
    <actions>    :=  <action>  | <action> "," <actions>
    <action>     :=  "depth="<num> | "backtrace" | "trace_on" | "trace_off" |
                     "color="<color> | "time="<time_spec> | "size="<num> |
                     "filter" | "notrace" | "hide" | "if:"<cond_spec>
    <time_spec>  :=  <num> [ <time_unit> ]
    <time_unit>  :=  "ns" | "nsec" | "us" | "usec" | "ms" | "msec" | "s" | "sec" | "m" | "min"
    <cond_spec>  :=  "arg"<num> <cond_op> <num>
    <cond_op>    :=  "==" | "!=" | ">" | ">=" | "<" | "<="

The `depth` trigger is to change filter depth during execution of the function.
It can be used to apply different filter depths for different functions.  And
the `backtrace` trigger is used to print a stack backtrace at replay time.

The color trigger is to change the color of the function in replay output.
The supported colors are `red`, `green`, `blue`, `yellow`, `magenta`, `cyan`,
`bold`, and `gray`.

The following example shows how triggers work.  We set a filter on function
`b()` with the `backtrace` action and change the maximum filter depth under
`b()` to 2.

    $ uftrace record ./abc
    $ uftrace replay -T 'b@filter,backtrace,depth=2'
    # DURATION    TID     FUNCTION
      backtrace [ 1234] | /* [ 0] main */
      backtrace [ 1234] | /* [ 1] a */
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The `trace_on` and `trace_off` actions (the `_` can be omitted as `traceon`
and `traceoff`) control whether uftrace shows functions or not.  The trigger
runs at replay time, not run time, so it can handle kernel functions as well.
Contrast this with triggers used under `uftrace record`.

The `time` trigger is to change time filter setting during execution of the
function.  It can be used to apply different time filter for different functions.

The `filter` and `notrace` triggers have same effect as `-F`/`--filter` and
`-N`/`--notrace` options respectively.  And it can have a condition.

The `hide` trigger has the same effect as `-H`/`--hide` option that hides the
given functions, but do not affect to the functions in their subtree unlike
the `notrace` trigger.


FIELDS
======
The uftrace allows for user to customize the replay output with a couple of
fields.  Here the field means info on the left side of the pipe (|) character.
By default it uses duration and tid fields, but you can use other fields in any
order like:

    $ uftrace replay -f time,delta,duration,addr
    #     TIMESTAMP      TIMEDELTA  DURATION     ADDRESS     FUNCTION
        74469.340757350              1.583 us       4004d0 | __monstartup();
        74469.340762221   4.871 us   0.766 us       4004f0 | __cxa_atexit();
        74469.340764847   2.626 us                  4006b1 | main() {
        74469.340765061   0.214 us                  400656 |   a() {
        74469.340765195   0.134 us                  400669 |     b() {
        74469.340765344   0.149 us                  40067c |       c() {
        74469.340765524   0.180 us   0.742 us       4004b0 |         getpid();
        74469.340766935   1.411 us   1.591 us       40067c |       } /* c */
        74469.340767195   0.260 us   2.000 us       400669 |     } /* b */
        74469.340767372   0.177 us   2.311 us       400656 |   } /* a */
        74469.340767541   0.169 us   2.694 us       4006b1 | } /* main */

Each field has following meaning:

 * tid: task id (obtained by gettid(2))
 * duration: function execution time
 * time: timestamp at the execution
 * delta: difference between two timestamp in a task
 * elapsed: elapsed time from the first timestamp
 * addr: address of the function
 * task: task name (comm)
 * module: library or executable name of the function

The default value is 'duration,tid'.  If given field name starts with "+", then
it'll be appended to the default fields.  So "-f +time" is as same as
"-f duration,tid,time".  And it also accepts a special field name of 'none'
which disables the field display and shows function output only.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-report`(1), `uftrace-info`(1)
