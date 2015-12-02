% FTRACE-LIVE(1) Ftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
ftrace-live - Trace functions in a command lively

SYNOPSIS
========
ftrace live [*options*] COMMAND [*command-options*]

DESCRIPTION
===========
This command runs COMMAND and prints its functions with time and thread info.  This is basically same as running `ftrace-record` and `ftrace-replay` command in turn, but it does not save data file.  This command accepts options that are accepted by either of record or replay command.

OPTIONS
=======
-b *SIZE*, \--buffer=*SIZE*
:   (XXX: no need to be configurable anymore?) Size of internal buffer which trace data will be saved.  Default size is 128KiB.

-d, \--debug
:   Print debug messages.  This option increases a debug level and can be used at most 3 times.

\--daemon
:   (XXX: rename to 'dont-wait' or 'keep') Trace daemon process which calls `fork`(2) and then `exit`(2).  Usually ftrace stops recording when its child exited but daemon process calls `exit`(2) before doing its real job (in the child process).  So this option is used to keep tracing such daemon processes.

-f *FILE*, \--file=*FILE*
:   (XXX: rename to 'data-directory'?) Specify trace data (directory) name.  Default is ftrace.dir

-F *FUNC*[,*FUNC*,...], \--filter=*FUNC*[,*FUNC*,...]
:   Set filter to trace selected functions only.  See *FILTERS*.

\--flat
:   Print flat format rather than C-like format.  This is usually for debugging and testing purpose.

\--library
:   (XXX: rename to 'ignore-nomcount' or 'allow-no-mcount`?)  Trace library source rather than executable itself.  When record record finds no mcount symbol in the executable it quits with an error message since it things there's no need to run the program.  However it's possible one is only interested functions in a library, in this case she can use this option so ftrace can keep running the program.

-L *PATH*, \--library-path=*PATH*
:   (XXX: this is only for testing!) Load necessary internal libraries from this path.

\--logfile=FILE
:   Save log message to this file instead of stderr.

\--no-plthook
:   Do not record library function invocations.  The ftrace traces library calls by hooking dynamic linker's resolve function in the PLT.  One can disable it with this option.

-N *FUNC*[,*FUNC*,...], \--notrace=*FUNC*[,*FUNC*,...]
:   Set filter not trace selected functions only.  See *FILTERS*.

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

    $ ftrace record -F b
    $ ftrace replay
    # DURATION    TID     FUNCTION
                [ 1234] |     b() {
       3.880 us [ 1234] |       c();
       5.475 us [ 1234] |     } /* b */

The second type is an opt-out filter; By default, it trace everything and when it executes one of given functions it stops tracing.  Also when it returns from the given funciton, it starts tracing again.

In the above example, you can omit the function b() and its children with -N option.

    $ ftrace record
    $ ftrace replay -N b
    # DURATION    TID     FUNCTION
     138.494 us [ 1234] | __cxa_atexit();
                [ 1234] | main() {
                [ 1234] |   a() {
       6.448 us [ 1234] |   } /* a */
       8.631 us [ 1234] | } /* main */

SEE ALSO
========
`ftrace-record`(1), `ftrace-replay`(1)
