% FTRACE-REPLAY(1) Ftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
ftrace-replay - Print recorded function trace

SYNOPSIS
========
ftrace replay [*options*]

DESCRIPTION
===========
This command prints trace data recorded using `ftrace-record`(1) command.  The traced functions are printed like a C program in time order.

OPTIONS
=======
-f *FILE*, \--file=*FILE*
:   Use this filename for trace data.  Default is `ftrace.dir`.

\--flat
:   Print flat format rather than C-like format.  This is usually for debugging and testing purpose.

-F *FUNC*, \--filter=FUNC
:   Set filter to trace selected functions only.  This option can be used more than once.  See *FILTERS*.

-N *FUNC*, \--notrace=*FUNC*
:   Set filter not trace selected functions only.  This option can be used more than once.  See *FILTERS*.

-T *TRG*, \--trigger=*TRG*
:   Set trigger on selected functions.  This option can be used more than once.  See *TRIGGERS*.

-t *TID*[,*TID*,...], \--tid=*TID*[,*TID*,...]
:   Only print functions from given threads.  To see the list of threads in the data file, you can use `ftrace-report --threads` or `ftrace-info` command.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

\--no-pager
:   Do not use pager

\--color=*VAL*
:   Enable or disable color on the output.  Possible values are "yes", "no" and "auto".  The "auto" is default and turn on coloring if stdout is a terminal.

\--disabled
:   Start ftrace with tracing disabled.  This is only meaningful when used with 'trace_on' trigger.

\--demangle=*TYPE*
:   Demangle C++ symbol names.  Possible values are "full", "simple" and "no".  Default is "simple" which ignores function arguments and template parameters.

FILTERS
=======
The ftrace support filtering only interested functions.  When ftrace is called it receives two types of function filter; opt-in filter with -F/--filter option and opt-out filter with -N/--notrace option.  These filters can be applied either record time or replay time.

The first one is an opt-in filter; By default, it doesn't trace anything and when it executes one of given functions it starts tracing.  Also when it returns from the given funciton, it stops again tracing.

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

    $ gcc -o abc abc.c

Normally ftrace will trace all the functions from `main()` to `c()`.

    $ ftrace ./abc
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

But when `-F b` filter option is used, it'll not trace `main()` and `a()` but only `b()` and `c()`.

    $ ftrace record ./abc
    $ ftrace replay -F b
    # DURATION    TID     FUNCTION
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */

The second type is an opt-out filter; By default, it trace everything and when it executes one of given functions it stops tracing.  Also when it returns from the given funciton, it starts tracing again.

In the above example, you can omit the function b() and its children with -N option.

    $ ftrace record ./abc
    $ ftrace replay -N b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

In addition, you can limit the print nesting level with -D option.

    $ ftrace record ./abc
    $ ftrace replay -D 3
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
                [ 1234] |     b() {
       5.475 us [ 1234] |     } /* b */
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

In the above example, it prints functions up to 3 depth, so leaf function c() was omitted.  Note that the -D option works with -F option.

You can also set triggers to filtered functions.  See *TRIGGERS* section below for details.


TRIGGERS
========
The ftrace support triggering some actions on selected function with or without filters.  Currently supported triggers are depth (for record and replay) and backtrace (for replay only).  The BNF for the trigger is like below:

    <trigger>  :=  <symbol> "@" <actions>
    <actions>  :=  <action>  | <action> "," <actions>
    <action>   :=  "depth=" <num> | "backtrace" | "trace_on" | "trace_off"

The depth trigger is to change filter depth during execution of the function.  It can be use to apply different filter depths for different functions.  And the backrace trigger is to print stack backtrace at replay time.

Following example shows how trigger works.  We set filter on function 'b' with the backtrace trigger and depth trigger of 2.

    $ ftrace record ./abc
    $ ftrace replay -F 'b@backtrace,depth=2'
    # DURATION    TID     FUNCTION
      backtrace [ 1234] | /* [ 0] main */
      backtrace [ 1234] | /* [ 1] a */
                [ 1234] |     b {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */

The 'traceon' and 'traceoff' (you can omit '_' between 'trace' and 'on/off') controls whether ftrace shows functions or not.  The trigger runs on replay time so that it can handle kernel functions as well.


SEE ALSO
========
`ftrace`(1), `ftrace-record`(1), `ftrace-report`(1), `ftrace-info`(1)
