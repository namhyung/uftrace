#
# gdb helper commands and functions for uftrace debugging
#
#  mcount tools
#
# Copyright (c) LG Electronics, 2018
#
# Authors:
#  Namhyung Kim <namhyung.kim@lge.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import gdb
from uftrace import rbtree, trigger, utils

filter_type = utils.CachedType("struct uftrace_filter")


def get_symbol_name(addr):
    try:
        block = gdb.block_for_pc(int(addr))
    except:
        try:
            return gdb.execute('info symbol ' + hex(addr), False, True).split(' ')[0]
        except:
            return '<unknown>'

    while block and not block.function:
        block = block.superblock

    if block is None:
        return '<unknown>'

    return block.function.print_name


class UftMcountData(gdb.Command):
    """Find mcount thread data of current thread and show return stacks."""

    def __init__(self):
        super(UftMcountData, self).__init__("uft-mcount-data", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        mtd = utils.gdb_eval_or_none("mtd")
        if mtd is None:
            gdb.write("no mtd found\n")
            return

        mtd_idx = mtd['idx']
        gdb.write("mtd: tid = {tid}, idx = {idx}\n".format(
            tid=mtd['tid'], idx=mtd_idx))

        rstack = mtd['rstack']
        for i in range(0, mtd_idx):
            cip = rstack[i]['child_ip']
            pip = rstack[i]['parent_ip']
            csym = get_symbol_name(cip)
            psym = get_symbol_name(pip)
            gdb.write("[{ind}] {child} <== {parent}\n".format(
                ind=i, child=csym, parent=psym))


UftMcountData()


class UftMcountFilter(gdb.Command):
    """List mcount filters."""

    def __init__(self):
        super(UftMcountFilter, self).__init__("uft-mcount-filters", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        tr = utils.gdb_eval_or_none("mcount_triggers")
        if tr is None:
            gdb.write("no filter/trigger found\n")
            return

        filter_ptr_type = filter_type.get_type().pointer()

        trigger.filter_print(None)
        for filt in rbtree.rb_for_each_entry(tr, filter_ptr_type, "node"):
            trigger.filter_print(filt)

UftMcountFilter()


class UftMcountTrigger(gdb.Command):
    """List mcount triggers."""

    def __init__(self):
        super(UftMcountTrigger, self).__init__("uft-mcount-triggers", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        tr = utils.gdb_eval_or_none("mcount_triggers")
        if tr is None:
            gdb.write("no filter/trigger found\n")
            return

        verbose = len(arg) > 0
        filter_ptr_type = filter_type.get_type().pointer()

        trigger.trigger_print(None, False)
        for filt in rbtree.rb_for_each_entry(tr, filter_ptr_type, "node"):
            trigger.trigger_print(filt, verbose)

UftMcountTrigger()


class UftMcountArgspec(gdb.Command):
    """List mcount arguments and return values."""

    def __init__(self):
        super(UftMcountArgspec, self).__init__("uft-mcount-args", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        tr = utils.gdb_eval_or_none("mcount_triggers")
        if tr is None:
            gdb.write("no filter/trigger found\n")
            return

        verbose = len(arg) > 0
        filter_ptr_type = filter_type.get_type().pointer()

        trigger.argspec_print(None, False)
        for filt in rbtree.rb_for_each_entry(tr, filter_ptr_type, "node"):
            trigger.argspec_print(filt, verbose)

UftMcountArgspec()
