#
# gdb helper commands and functions for uftrace debugging
# copied from the Linux kernel source
#
#  loader module
#
# Copyright (c) Siemens AG, 2012, 2013
#
# Authors:
#  Jan Kiszka <jan.kiszka@siemens.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import os

sys.path.insert(0, os.path.dirname(__file__) + "/gdb")

try:
    gdb.parse_and_eval("0")
    gdb.execute("", to_string=True)
except:
    gdb.write("NOTE: gdb 7.2 or later required for helper scripts to work.\n")
else:
    import uftrace.utils
    import uftrace.lists
    import uftrace.plthook
    import uftrace.mcount
    import uftrace.rbtree
    import uftrace.trigger
