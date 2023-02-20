#
# gdb helper commands and functions for uftrace debugging
#
#  filter and trigger tools
#
# Copyright (c) LG Electronics, 2018
#
# Authors:
#  Namhyung Kim <namhyung.kim@lge.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import gdb
from uftrace import lists, utils

filter_type  = utils.CachedType("struct uftrace_filter")
trigger_type = utils.CachedType("struct uftrace_trigger")
argspec_type = utils.CachedType("struct uftrace_arg_spec")

TRIGGER_FLAGS = [ "DEPTH", "FILTER", "BACKTRACE", "TRACE",
                  "TRACE_ON", "TRACE_OFF", "ARGUMENT", "RECOVER",
                  "RETVAL", "COLOR", "TIME_FILTER", "READ",
                  "FINISH", "AUTO_ARGS" ]

TR_FLAG_FILTERS = 1 + 2 + 1024       # DEPTH | FILTER | TIME_FILTER
TR_FLAG_ARGS    = 64 + 256 + 8192    # ARGUMENT | RETVAL | AUTO_ARGS
TR_FLAG_READ    = 2048

ARG_TYPE_INDEX = 0
ARG_TYPE_FLOAT = 1
ARG_TYPE_REG   = 2
ARG_TYPE_STACK = 3

ARG_FMT_AUTO = 0
ARG_FMT_STR  = "diuxscfSpe"


def filter_flag(tr):
    flag = tr['flags']
    fmode = tr['fmode']

    f = 'D' if flag & 1 else ' '
    if flag & 2:
        f += 'F' if fmode == 1 else 'N'
    f += 't' if flag >= 1024 else ' '

    return f


def filter_print(filt):
    if filt is None:
        gdb.write("{start:>16}   {end:<16}   {flag:4}  {name}\n".
                  format(start="Start", end="End", flag="Flag", name="Name"))
        return

    tr = filt['trigger']
    flags = tr['flags']

    if (flags & TR_FLAG_FILTERS) == 0:
        return

    gdb.write("{start:>16} - {end:<16} : {flag:4}  {name}\n".
              format(start=hex(filt['start']), end=hex(filt['end']),
                     flag=filter_flag(tr), name=filt['name'].string()))


def trigger_flag(tr):
    flags = tr['flags']
    s = []

    for bit, flag in enumerate(TRIGGER_FLAGS):
        if flags & (1 << bit):
            s.append(flag)

    return '|'.join(s)


def trigger_print(filt, verbose):
    if filt is None:
        gdb.write("{start:>16}   {end:<16}   {flag:>6}  {name}\n".
                  format(start="Start", end="End", flag="Flags", name="Name"))
        return

    tr = filt['trigger']
    gdb.write("{start:>16} - {end:<16} : {flag:>6}  {name}\n".
              format(start=hex(filt['start']), end=hex(filt['end']),
                     flag=hex(tr['flags']), name=filt['name'].string()))
    if verbose:
        gdb.write("  triggers = {flags}\n".format(flags=trigger_flag(tr)))


def trigger_argspec(tr):
    argspec_ptr_type = argspec_type.get_type().pointer()
    s = []

    for arg in lists.list_for_each_entry(tr['pargs'], argspec_ptr_type, 'list'):
        t = arg['type']
        if t == ARG_TYPE_INDEX:
            idx = int(arg['idx'])
            if idx == 0:
                a = 'retval'
            else:
                a = 'arg{i}'.format(i=int(arg['idx']))
        elif t == ARG_TYPE_FLOAT:
            a = 'fparg{i}'.format(i=int(arg['idx']))
        elif t == ARG_TYPE_REG:
            a = 'reg{i}'.format(i=int(arg['reg_idx']))
        elif t == ARG_TYPE_STACK:
            a = 'stack+{i}'.format(i=int(arg['stack_ofs']))

        f = arg['fmt']
        if f != ARG_FMT_AUTO:
            a += "/{fmt}{sz}".format(fmt=ARG_FMT_STR[f], sz=arg['size']*8)

        s.append(a)

    return ','.join(s)


def argspec_flag(flags):
    if flags >= 8192:  # AUTO_ARGS
        return "AA"

    f  = 'A' if flags &  64 else ' '
    f += 'R' if flags & 256 else ' '

    return f


def argspec_print(filt, verbose):
    if filt is None:
        gdb.write("{start:>16}   {end:<16}   {flag:4}  {name}\n".
                  format(start="Start", end="End", flag="Flag", name="Name"))
        return

    tr = filt['trigger']
    flags = tr['flags']

    if (flags & TR_FLAG_ARGS) == 0:
        return

    gdb.write("{start:>16} - {end:<16} : {flag:4}  {name}\n".
              format(start=hex(filt['start']), end=hex(filt['end']),
                     flag=argspec_flag(flags), name=filt['name'].string()))
    if verbose:
        gdb.write("  argspec = {spec}\n".format(spec=trigger_argspec(tr)))
