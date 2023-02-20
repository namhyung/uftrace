#
# gdb helper commands and functions for uftrace debugging
# copied from the Linux kernel source (module tools)
#
#  plthook tools
#
# Copyright (c) Siemens AG, 2013
# Copyright (c) LG Electronics, 2018
#
# Authors:
#  Jan Kiszka <jan.kiszka@siemens.com>
#  Namhyung Kim <namhyung.kim@lge.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import os

import gdb
from uftrace import lists, utils

plthook_data_type = utils.CachedType("struct plthook_data")


def plthook_list():
    plthook_modules = utils.gdb_eval_or_none("plthook_modules")
    if plthook_modules is None:
        return

    pd_ptr_type = plthook_data_type.get_type().pointer()

    for module in lists.list_for_each_entry(plthook_modules, pd_ptr_type, "list"):
        yield module


def find_module_by_name(name):
    for module in plthook_list():
        if os.path.basename(module['mod_name'].string()) == name:
            return module
    return None


class UftPlthookData(gdb.Command):
    """List currently loaded plthook modules."""

    def __init__(self):
        super(UftPlthookData, self).__init__("uft-plthook-data", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        gdb.write("{id:>16}  {addr:>16}  {name:<32}\n".format(
            id="Module Id", name="Name", addr="Base Address"))

        for module in plthook_list():
            gdb.write("{id:>16}  {addr:>16}  {name:<32}\n".format(
                id=hex(module['module_id']),
                addr=hex(module['base_addr']),
                name=os.path.basename(module['mod_name'].string())))


UftPlthookData()
