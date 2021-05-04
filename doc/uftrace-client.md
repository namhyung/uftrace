% UFTRACE-RECORD(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% Sep, 2018

NAME
====
uftrace-client - Send commands to a running uftrace target


SYNOPSIS
========
uftrace client [*options*] COMMAND [*command-options*]


DESCRIPTION
===========
This command forwards its options to a uftrace daemon instance, according to its
PID.  The daemon then applies the given options dynamically at runtime.

NOTE: The daemon is enabled by default in `uftrace record` or `uftrace live`.


CLIENT OPTIONS
==============

-p *PID*, \--pid=*PID*
:   Communicate with daemon with given *PID*.

-A *SPEC*, \--argument=*SPEC*
:   Record function arguments.  This option can be used more than once.
    Implies \--srcline.  See *ARGUMENTS*.

-R *SPEC*, \--retval=*SPEC*
:   Record function return values.  This option can be used more than once.
    Implies \--srcline.  See *ARGUMENTS*.

-U *FUNC*, \--unpatch=*FUNC*
:   Do not apply dynamic patching for FUNC.  This option can be used more than once.

-W, \--watch=*POINT*
:   Add watch point to display POINT if the value is changed.  See *WATCH POINT*.


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

-D *DEPTH*, \--depth=*DEPTH*
:   Set global trace limit in nesting level.  See *FILTERS*.

-t *TIME*, \--time-filter=*TIME*
:   Do not show functions which run under the time threshold.  If some functions
    explicitly have the 'trace' trigger applied, those are always traced
    regardless of execution time.  See *FILTERS*.

\--match=*TYPE*
:   Use pattern match using TYPE.  Possible types are `regex` and `glob`.
    Default is `regex`.


FILTERS
=======
The uftrace tool supports filtering out uninteresting functions.  Filtering is
highly recommended since it helps users focus on the interesting functions and
reduces the data size.  When uftrace is called it receives two types of function
filter; an opt-in filter with `-F`/`--filter` and an opt-out filter with
`-N`/`--notrace`.  These filters can be applied either at record time or
replay time.

For example, consider a simple program which calls `a()`, `b()` and `c()` in turn, twice.

    $ cat abc2.c
    #include <unistd.h>

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
        sleep(2);
        a();
        return 0;
    }

    $ gcc -pg -o abc2 abc2.c

Normally uftrace will trace all the functions from `main()` to `c()`.

    $ uftrace record ./abc2
    $ uftrace replay
    # DURATION     TID     FUNCTION
    2.392 us [  1234] | __monstartup();
    1.526 us [  1234] | __cxa_atexit();
             [  1234] | main() {
             [  1234] |   a() {
             [  1234] |     b() {
    0.185 us [  1234] |       c();
    0.909 us [  1234] |     } /* b */
    1.366 us [  1234] |   } /* a */
    2.000  s [  1234] |   sleep();
             [  1234] |   a() {
             [  1234] |     b() {
    0.542 us [  1234] |       c();
    2.135 us [  1234] |     } /* b */
    3.308 us [  1234] |   } /* a */
    2.000  s [  1234] | }

Say we filter out `b()` with `-N b` at startup, and we want to trace it again
after the `sleep()` call. We can use the `-F b -F a` option in the client to
revert the original setting.

    $ uftrace -N b record ./abc2&
    $ uftrace -F a -F b client -p $(pidof abc2)  # During the sleep() call
    $ uftrace replay
    # DURATION     TID     FUNCTION
    1.708 us [  1234] | __monstartup();
    1.411 us [  1234] | __cxa_atexit();
             [  1234] | main() {
    1.141 us [  1234] |   a();
    2.000  s [  1234] |   sleep();
             [  1234] |   a() {
             [  1234] |     b() {
    0.351 us [  1234] |       c();
    1.689 us [  1234] |     } /* b */
    3.443 us [  1234] |   } /* a */
    2.000  s [  1234] | }

In addition, you can limit the nesting level of functions with the `-D` option.

    $ uftrace record ./abc2&
    $ uftrace -D 2 client -p $(pidof abc2)
    $ uftrace replay
    # DURATION     TID     FUNCTION
    1.989 us [  1234] | __monstartup();
    1.192 us [  1234] | __cxa_atexit();
             [  1234] | main() {
             [  1234] |   a() {
             [  1234] |     b() {
    0.166 us [  1234] |       c();
    0.841 us [  1234] |     } /* b */
    1.293 us [  1234] |   } /* a */
    2.000  s [  1234] |   sleep();
    1.413 us [  1234] |   a();
    2.000  s [  1234] | }

In the above example, after the client command, uftrace only records functions
up to a depth of 2.

Sometimes it's useful to see long-running functions only.  This is good because
there are usually many tiny functions that are not interesting.
The `-t`/`--time-filter` option implements the time-based filter that only
records functions which run longer than the given threshold.  In the above
example, the user might want to see functions running more than
2 micro-seconds like below:

    $ uftrace record ./abc2&
    $ uftrace -t 2us client -p $(pidof abc2)
    $ uftrace replay
    # DURATION     TID     FUNCTION
    1.997 us [  1234] | __monstartup();
    1.218 us [  1234] | __cxa_atexit();
             [  1234] | main() {
             [  1234] |   a() {
             [  1234] |     b() {
    0.174 us [  1234] |       c();
    0.994 us [  1234] |     } /* b */
    1.534 us [  1234] |   } /* a */
    2.000  s [  1234] |   sleep();
    2.109 us [  1234] |   a();
    2.000  s [  1234] | }

The `-t`/`--time-filter` option works for user-level functions only.  It does
not work for recording kernel functions, but they can be hidden in replay, report,
dump and graph commands with `-t`/`--time-filter` option.

You can also set triggers on filtered functions.  See *TRIGGERS* section below
for details.


TRIGGERS
========
The uftrace tool supports triggering actions on selected function calls (with or
without filters) and/or signals.  The client can also forward triggers to a daemon.
Please see the *TRIGGERS* section of the record man page.


ARGUMENTS
=========
The uftrace tool supports recording function arguments and/or return values
using the -A/\--argument and -R/\--retval options respectively.
The syntax is very similar to that of triggers:

    <argument>    :=  <symbol> [ "@" <specs> ]
    <specs>       :=  <spec> | <spec> "," <spec>
    <spec>        :=  ( <int_spec> | <float_spec> | <ret_spec> )
    <int_spec>    :=  "arg" N [ "/" <format> [ <size> ] ] [ "%" ( <reg> | <stack> ) ]
    <float_spec>  :=  "fparg" N [ "/" ( <size> | "80" ) ] [ "%" ( <reg> | <stack> ) ]
    <ret_spec>    :=  "retval" [ "/" <format> [ <size> ] ]
    <format>      :=  "d" | "i" | "u" | "x" | "s" | "c" | "f" | "S" | "p"
    <size>        :=  "8" | "16" | "32" | "64"
    <reg>         :=  <arch-specific register name>  # "rdi", "xmm0", "r0", ...
    <stack>       :=  "stack" [ "+" ] <offset>

The -A/\--argument option takes a symbol name pattern and its optional specs.
The spec is started by argN where N is an index of the arguments.  The index
starts from 1 and corresponds to the argument passing order of the calling
convention on the system.  Note that the indexes of arguments are separately
counted for integer (or pointer) and floating-point type, and they can interfere
depending on the calling convention.  The argN is for integer arguments and
fpargN is for floating-point arguments.

Users can optionally specify a format and size for the arguments and/or return
values.  The "d" format or without format field, uftrace treats them as
'long int' type for integers and 'double' for floating-point numbers.
The "i" format makes it signed integer type and "u" format is for unsigned
type.  Both are printed as decimal while "x" format makes it printed as
hexadecimal.  The "s" format is for null-terminated string type and "c" format
is for character type.  The "f" format is for floating-point type and is
meaningful only for return value (generally).  Note that fpargN doesn't take
the format field since it's always floating-point.  The "S" format is for
std::string, but it only supports libstdc++ library as of yet.  Finally,
the "p" format is for function pointer. Once the target address is recorded,
it will be displayed as function name.

Please beware when using string type arguments since it can crash the program
if the (pointer) value is invalid.  Actually uftrace tries to keep track of
valid ranges of process address space but it might miss some corner cases.

It is also possible to specify a certain register name or stack offset for
arguments (but not for return value).  The following register names can be used
for argument:

 * x86: rdi, rsi, rdx, rcx, r8, r9 (for integer), xmm[0-7] (for floating-point)
 * arm: r[0-3] (for integer), s[0-15] or d[0-7] (for floating-point)

Examples are below:

    $ uftrace record ./abc2&
    $ uftrace -A a@arg1 -R a@retval client -p $(pidof abc2)
    $ uftrace replay
    # DURATION     TID     FUNCTION
    8.045 us [  1234] | __monstartup();
    5.763 us [  1234] | __cxa_atexit();
             [  1234] | main() {
             [  1234] |   a() {
             [  1234] |     b() {
    0.166 us [  1234] |       c();
    0.944 us [  1234] |     } /* b */
    2.109 us [  1234] |   } /* a */
    2.000  s [  1234] |   sleep();
             [  1234] |   a(0) {
             [  1234] |     b() {
    0.310 us [  1234] |       c();
    1.734 us [  1234] |     } /* b */
    4.376 us [  1234] |   } = 0; /* a */
    2.000  s [  1234] | }

Note that these arguments and return value are recorded only if the executable
was built with the `-pg` option.  Executables built with `-finstrument-functions`
will ignore it except for library calls.  Recording of arguments and return
values only works with user-level functions for now.

If the target program is built with debug info like DWARF, uftrace can identify
number of arguments and their types automatically (when built with libdw).
Also arguments and return value of some well-known library functions are
provided even if the debug info is not available.  In these cases user don't
need to specify spec of the arguments and return value manually - just a
function name (or pattern) is enough.  In fact, manual argspec will suppress
the automatic argspec.


WATCH POINT
===========
The uftrace watch point is to display certain value only if it's changed.
It's conceptually same as other debuggers but only works at function entry and exit
so it might miss some updates.

As of now, following watch points are supported:

 * "cpu" : cpu number current task is running on

Like read triggers, the result is displayed as event (comment):

    $ uftrace -W cpu tests/t-abc
    # DURATION     TID     FUNCTION
                [ 19060] | main() {
                [ 19060] |   /* watch:cpu (cpu=8) */
                [ 19060] |   a() {
                [ 19060] |     b() {
                [ 19060] |       c() {
       2.365 us [ 19060] |         getpid();
       8.002 us [ 19060] |       } /* c */
       8.690 us [ 19060] |     } /* b */
       9.350 us [ 19060] |   } /* a */
      12.479 us [ 19060] | } /* main */


SEE ALSO
========
`uftrace`(1), `uftrace-record`(1), `uftrace-replay`(1),
`uftrace-report`(1), `uftrace-recv`(1), `uftrace-graph`(1), `uftrace-script`(1),
`uftrace-tui`(1)
