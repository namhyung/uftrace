% FTRACE(1) Ftrace User Manuals
% Namhyung Kim <namhyung@gmail.com>
% March, 2015

NAME
====
ftrace - A function tracer

SYNOPSIS
========
ftrace [*record*|*replay*|*live*|*report*|*info*] [*options*] COMMAND [*command-options*]

DESCRIPTION
===========
The ftrace is a function tracer that traces an execution of given COMMAND in the function level.  The COMMAND should be a C/C++ executable built with compiler instrumentation (-pg).  Also the COMMAND needs to have an ELF symbol table (i.e. not `strip`(1)-ed) in order to print the name of traced functions.

This command consists of a number of sub-commands like `git`(1) or `perf`(1).  The below is a short description of each sub-commands.  For more detailed information, see its manual page.  The options in this page can be given to any sub-command also.

For convenience, if no sub-command is given, it'd act like `live` sub-command which runs `record` and `replay` sub-command in turn.  See `ftrace-live`(1) for options belongs to the `live` sub-command.  For more detailed analysis, it'd be better using `ftrace-record`(1) to save trace data, and then analyze it with other ftrace commands like `ftrace-report`(1), `ftrace-info`(1) or `ftrace-replay`(1).

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

OPTIONS
=======
-?, \--help
:   Print help message and list of options with description

\--usage
:   Print usage string

-V, \--version
:   Print program version

-d, \--debug
:   Print debug messages.  This option increases a debug level and can be used at most 3 times.

--logfile=*FILE*
:   Save warning and debug messages into this file instead of stderr.

SEE ALSO
========
`ftrace-live`(1), `ftrace-record`(1), `ftrace-replay`(1), `ftrace-report`(1), `ftrace-info`(1)
