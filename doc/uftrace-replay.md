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
This command prints trace data recorded using `uftrace-record`(1) command.  The traced functions are printed like a C program in time order.


OPTIONS
=======
\--flat
:   Print flat format rather than C-like format.  This is usually for debugging and testing purpose.

-F *FUNC*, \--filter=FUNC
:   Set filter to trace selected functions only.  This option can be used more than once.  See *FILTERS*.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not trace selected functions only.  This option can be used more than once.  See *FILTERS*.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See *TRIGGERS*.

-t *TID*[,*TID*,...], \--tid=*TID*[,*TID*,...]
:   Only print functions from given threads.  To see the list of threads in the data file, you can use `uftrace-report --threads` or `uftrace-info` command.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

\--disable
:   Start uftrace with tracing disabled.  This is only meaningful when used with 'trace_on' trigger.

--column-view
:   Show each task in separate column.  This makes easy to distinguish functions in different tasks.

--column-offset=*DEPTH*
:   When `--column-view` option is used, this option specifies the amount of offsets between each task.  Default is 8.

--task-newline
:   Interleave a new line when task is changed.  This makes easy to distinguish functions in different tasks.


FILTERS
=======
The uftrace support filtering only interested functions.  When uftrace is called it receives two types of function filter; opt-in filter with -F/--filter option and opt-out filter with -N/--notrace option.  These filters can be applied either record time or replay time.

The first one is an opt-in filter; By default, it doesn't show anything and when it meets one of given functions it starts printing.  Also when it returns from the given function, it stops again printing.

For example, suppose a simple program which calls a(), b() and c() in turn.

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

But when `-F b` filter option is used, it'll not trace `main()` and `a()` but only `b()` and `c()`.  Note that the filter was set on 'uftrace replay', not record time.

    $ uftrace record ./abc
    $ uftrace replay -F b
    # DURATION    TID     FUNCTION
                [ 1234] | b() {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The second type is an opt-out filter; When used, it shows everything and stops printing once it meets one of given functions.  Also when it returns from the given funciton, it starts printing again.

In the above example, you can omit the function b() and its children with -N option.

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

In the above example, it prints functions up to 3 depth, so leaf function c() was omitted.  Note that the -D option also works with -F option.

You can also set triggers to filtered functions.  See *TRIGGERS* section below for details.


TRIGGERS
========
The uftrace support triggering some actions on selected function with or without filters.  Currently supported triggers are depth, backtrace, trace_on and trace_off.  The BNF for the trigger is like below:

    <trigger>  :=  <symbol> "@" <actions>
    <actions>  :=  <action>  | <action> "," <actions>
    <action>   :=  "depth=" <num> | "backtrace" | "trace_on" | "trace_off"

The depth trigger is to change filter depth during execution of the function.  It can be use to apply different filter depths for different functions.  And the backrace trigger is to print stack backtrace at replay time.

Following example shows how trigger works.  We set filter on function 'b' with the backtrace trigger and depth trigger of 2.

    $ uftrace record ./abc
    $ uftrace replay -F 'b@backtrace,depth=2'
    # DURATION    TID     FUNCTION
      backtrace [ 1234] | /* [ 0] main */
      backtrace [ 1234] | /* [ 1] a */
                [ 1234] | b {
       3.880 us [ 1234] |   c();
       5.475 us [ 1234] | } /* b */

The 'traceon' and 'traceoff' (you can omit '_' between 'trace' and 'on/off') controls whether uftrace shows functions or not.  The trigger runs on replay time so that it can handle kernel functions as well.


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-report`(1), `uftrace-info`(1)
