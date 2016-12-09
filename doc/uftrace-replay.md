% UFTRACE-REPLAY(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% May, 2016

NAME
====
uftrace-replay - Print recorded function trace


SYNOPSIS
========
uftrace replay [*options*]


DESCRIPTION
===========
This command prints trace data recorded using the `uftrace-record`(1) command.  The traced functions are printed like a C program in time order.


OPTIONS
=======
\--flat
:   Print flat format rather than C-like format.  This is usually for debugging and testing purpose.

-F *FUNC*, \--filter=*FUNC*
:   Set filter to trace selected functions only.  This option can be used more than once.  See *FILTERS*.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not to trace selected functions (or the functions called underneath them).  This option can be used more than once.  See *FILTERS*.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See *TRIGGERS*.

-t *TIME*, \--time-filter=*TIME*
:   Do not show functions which run under the time threshold.  If some functions explicitly have the 'trace' trigger applied, those are always traced regardless of execution time.

\--tid=*TID*[,*TID*,...]
:   Only print functions called by the given threads.  To see the list of threads in the data file, you can use `uftrace report --threads` or `uftrace info`.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

-f *FIELD*, \--output-fields=*FIELD*
:   Customize field in the output.  Possible values are: duration, tid, time, delta and addr.  Multiple fields can be set by using comma.  Special field of 'none' can be used (solely) to hide all fields.  Default is 'duration,tid'.  See *FIELDS*.

\--disable
:   Start uftrace with tracing disabled.  This is only meaningful when used with a `trace_on` trigger.

--column-view
:   Show each task in separate column.  This makes easy to distinguish functions in different tasks.

--column-offset=*DEPTH*
:   When `--column-view` option is used, this option specifies the amount of offset between each task.  Default is 8.

--task-newline
:   Interleave a new line when task is changed.  This makes easy to distinguish functions in different tasks.

--no-comment
:   Do not show comments of returned functions.

-k, \--kernel
:   Trace kernel functions as well as user functions.

\--kernel-full
:   Show all kernel functions called outside of user functions.  This option is the inverse of `--kernel-skip-out`.  Implies `--kernel`.

\--kernel-skip-out
:   Do not show kernel functions called outside of user functions.  This option is deprecated and set to true by default.

\--kernel-only
:   Show kernel functions only without user functions.  Implies `--kernel`.


FILTERS
=======
The uftrace tool supports filtering out uninteresting functions.  When uftrace is called it receives two types of function filter; an opt-in filter with `-F`/`--filter` and an opt-out filter with `-N`/`--notrace`.  These filters can be applied either at record time or replay time.

The first one is an opt-in filter. By default, it doesn't show anything. But when one of the specified functions is met, printing is started.  When the function returns, printing is stopped again.

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

But when the `-F b` filter option is used, it will not show `main()` or `a()` but only `b()` and `c()`.  Note that the filter was set on `uftrace replay`, not at record time.

    $ uftrace record ./abc
    $ uftrace replay -F b
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The second type of filter is opt-out. When used, everything is shown by default, but printing stops once one of the specified functions is met.  When the given function returns, printing is started again.

In the above example, you can omit the function `b()` and all calls it makes with the `-N` option.

    $ uftrace record ./abc
    $ uftrace replay -N b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

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

In the above example, uftrace only prints functions up to a depth of 3, so leaf function `c()` was omitted.  Note that the `-D` option also works with `-F`.

Sometimes it's useful to see long-running functions only.  This is good because there are usually many tiny functions that are not interesting.  The `-t`/`--time-filter` option implements the time-based filter that only records functions which run longer than the given threshold.  In the above example, the user might want to see functions running more than 5 microseconds like below:

    $ uftrace record ./abc
    $ uftrace replay -t 5us
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       5.475 us [ 1234] |     b();
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

You can also see replay output with different time threshold for the same recorded data.

    $ uftrace replay -t 6us
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
       6.448 us [ 1234] |   a();
       8.631 us [ 1234] | } /* main */

You can also set triggers on filtered functions.  See *TRIGGERS* section below for details.


TRIGGERS
========
The uftrace tool supports triggering actions on selected function calls with or without filters.  Currently supported triggers are `depth`, `backtrace`, `trace_on` and `trace_off`.  The BNF for trigger specifications is like below:

    <trigger>    :=  <symbol> "@" <actions>
    <actions>    :=  <action>  | <action> "," <actions>
    <action>     :=  "depth="<num> | "backtrace" | "trace_on" | "trace_off" | "color="<color> | "time="<time_spec>
    <time_spec>  :=  <num> [ <time_unit> ]
    <time_unit>  :=  "ns" | "us" | "ms" | "s"

The `depth` trigger is to change filter depth during execution of the function.  It can be used to apply different filter depths for different functions.  And the `backtrace` trigger is used to print a stack backtrace at replay time.

The color trigger is to change the color of the function in replay output.  The supported colors are `red`, `green`, `blue`, `yellow`, `magenta`, `cyan`, `bold`, and `gray`.

The following example shows how triggers work.  We set a filter on function `b()` with the `backtrace` action and change the maximum filter depth under `b()` to 2.

    $ uftrace record ./abc
    $ uftrace replay -F 'b@backtrace,depth=2'
    # DURATION    TID     FUNCTION
      backtrace [ 1234] | /* [ 0] main */
      backtrace [ 1234] | /* [ 1] a */
                [ 1234] | b {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The `traceon` and `traceoff` actions (the `_` can be omitted from `trace_on` and `trace_off`) control whether uftrace shows functions or not.  The trigger runs at replay time, not run time, so it can handle kernel functions as well. Contrast this with triggers used under `uftrace record`.

The 'time' trigger is to change time filter setting during execution of the function.  It can be used to apply different time filter for different functions.


FIELDS
======
The uftrace allows for user to customize the replay output with a couple of fields.  Here the field means info on the left side of the pipe (|) character.  By default it uses duration and tid fields, but you can use other fields in any order like:

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
 * addr: address of the function

The default value is 'duration,tid'.  And it also accepts a special field name of 'none' which disables the field display and shows function output only.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-report`(1), `uftrace-info`(1)
