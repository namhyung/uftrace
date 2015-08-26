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

-F *FUNC*[,*FUNC*,...], \--filter=FUNC[,*FUNC*,...]
:   Set filter to trace selected functions only.  See *FILTERS*.

-N *FUNC*[,*FUNC*,...], \--notrace=*FUNC*[,*FUNC*,...]
:   Set filter not trace selected functions only.  See *FILTERS*.

-T *TID*[,*TID*,...], \--tid=*TID*[,*TID*,...]
:   Only print functions from given threads.  To see the list of threads in the data file, you can use `ftrace-report --threads` or `ftrace-info` command.

-D *DEPTH*, \--depth *DEPTH*
:   Set trace limit in nesting level.

\--backtrace
:   Print backtrace of filtered function.  This option requires -F option.

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

SEE ALSO
========
`ftrace`(1), `ftrace-record`(1), `ftrace-report`(1), `ftrace-info`(1)
