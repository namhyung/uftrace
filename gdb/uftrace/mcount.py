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
import os
from uftrace import utils


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
