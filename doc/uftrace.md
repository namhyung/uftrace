% UFTRACE(1) Uftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
uftrace - Function graph tracer for userspace

SYNOPSIS
========
uftrace [*record*|*replay*|*live*|*report*|*info*|*dump*|*recv*] [*options*] COMMAND [*command-options*]

DESCRIPTION
===========
The uftrace is a function tracer that traces an execution of given COMMAND in the function level.  The COMMAND should be a C/C++ executable built with compiler instrumentation (-pg).  Also the COMMAND needs to have an ELF symbol table (i.e. not `strip`(1)-ed) in order to print the name of traced functions.

This command consists of a number of sub-commands like `git`(1) or `perf`(1).  The below is a short description of each sub-commands.  For more detailed information, see its manual page.  The options in this page can be given to any sub-command also.

For convenience, if no sub-command is given, it'd act like `live` sub-command which runs `record` and `replay` sub-command in turn.  See `uftrace-live`(1) for options belongs to the `live` sub-command.  For more detailed analysis, it'd be better using `uftrace-record`(1) to save trace data, and then analyze it with other uftrace commands like `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1) or `uftrace-replay`(1).

SUB-COMMANDS
============
record
:   Run a given command and save trace data in a data file or directory.

replay
:   Print recorded function trace data with time duration.

live
:   Do live tracing.  Print function trace of the given command.

report
:   Print various statistics and summary of the recorded trace data.

info
:   Print side-band information like OS version, CPU info, command line and so on.

dump
:   Print raw tracing data in the data files.

recv
:   Save tracing data sent to network

OPTIONS
=======
-?, \--help
:   Print help message and list of options with description

\--usage
:   Print usage string

-V, \--version
:   Print program version

-v, \--verbose
:   Print verbose messages.  This option increases a debug level and can be used at most 3 times.

\--debug
:   Print debug messages.  This option is same as -v/\--verbose and provides only for backward compatibility.

\--debug-domain=*DOMAIN*[,*DOMAIN*, ...]
:   Limit debug messages belong to DOMAIN to be printed.  Available domains are: ftrace, symbol, demangle, filter, fstack, session, kernel, mcount.  The domains can have an their own debug level optionally (preceded by a colon).  For example, `-v --debug-domain=filter:2` will apply debug level of 2 to "filter" domain and apply debug level of 1 to others.

-d *DATA*, \--data=*DATA*
:   Specify name of trace data (directory).  Default is `uftrace.data`.

\--logfile=*FILE*
:   Save warning and debug messages into this file instead of stderr.

\--color=*VAL*
:   Enable or disable color on the output.  Possible values are "yes", "no" and "auto".  The "auto" is default and turn on coloring if stdout is a terminal.

\--no-pager
:   Do not use pager

SEE ALSO
========
`uftrace-live`(1), `uftrace-record`(1), `uftrace-replay`(1), `uftrace-report`(1), `uftrace-info`(1), `uftrace-dump`(1), `uftrace-recv`(1)
