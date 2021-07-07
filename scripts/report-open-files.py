#
# report-open-files.py
#
# uftrace-option: --nest-libcall -T open@filter,arg1/s,arg2/e:uft_open_flag,retval/i -T openat@filter,arg1,arg2/s,arg3/e:uft_open_flag,retval/i -T fopen@filter,arg1/s,arg2/s,retval
#

from __future__ import print_function
import os

UFTRACE_FUNC = [ "open", "openat", "fopen" ]

UFT_OPEN_MODE_MASK = 0x3
uft_open_mode = [ "O_RDONLY", "O_WRONLY", "O_RDWR", "O_XXX" ]

uft_open_flag = {
        "O_CREAT": 0100,
        "O_EXCL": 0200,
        "O_NOCTTY": 0400,
        "O_TRUNC": 01000,
        "O_APPEND": 02000,
        "O_NONBLOCK": 04000,
        "O_DSYNC": 010000,
        "O_ASYNC": 020000,
        "O_DIRECT": 040000,
        "O_LARGEFILE": 0100000,
        "O_DIRECTORY": 0200000,
        "O_NOATIME": 01000000,
        "O_CLOEXEC": 02000000,
        "O_SYNC": 04010000,
        "O_PATH": 010000000,
}

open_map = {}
openat_map = {}
fopen_map = {}
open_pathname = ""

def uftrace_begin():
    pass

def uftrace_entry(ctx):
    global open_pathname
    if ctx.has_key("args"):
        open_pathname = ctx["args"][0]
        if ctx["name"] == "open":
            open_mode = ctx["args"][1]
            open_map[open_pathname] = open_mode
        elif ctx["name"] == "openat":
            open_mode = ctx["args"][2]
            openat_map[open_pathname] = open_mode
        elif ctx["name"] == "fopen":
            open_mode = ctx["args"][1]
            fopen_map[open_pathname] = open_mode

def uftrace_exit(ctx):
    global open_pathname
    if ctx.has_key("retval"):
        if ctx["name"] == "open":
            #if ctx["retval"] == -1:
            if ctx["retval"] == 18446744073709551615:
                del open_map[open_pathname]
        elif ctx["name"] == "openat":
            #if ctx["retval"] == -1:
            if ctx["retval"] == 18446744073709551615:
                del openat_map[open_pathname]
        elif ctx["name"] == "fopen":
            if ctx["retval"] == 0:
                del fopen_map[open_pathname]

def uftrace_end():
    num_open_files = len(open_map) + len(fopen_map)

    pid = os.getpid()
    with open("/proc/%s/comm" % pid) as proc_comm:
        comm = proc_comm.read()[:-1]
        print("  # %d files are opened by '%s' (pid: %d)\n" % (num_open_files, comm, pid))

    if num_open_files == 0:
        return

    max_mode_len = 16
    for mode in open_map.values():
        mode_str = get_mode_str(mode)
        max_mode_len = max(max_mode_len, len(mode_str))
    for mode in openat_map.values():
        mode_str = get_mode_str(mode)
        max_mode_len = max(max_mode_len, len(mode_str))
    for mode_str in fopen_map.values():
        max_mode_len = max(max_mode_len, len(mode_str))

    open_mode_len = len("open mode")
    width = max_mode_len - open_mode_len
    print("  %*s%s    %-#50s" % (width, "", "open mode", "pathname"))
    print("  ", end='')
    for i in range(0, width + open_mode_len + 1):
        print("=", end='')
    print("  ================================================")
    for open_file, mode in open_map.items():
        mode_str = get_mode_str(mode)
        width = max_mode_len - len(mode_str)
        print("  %*s%s    %s" % (width, "", mode_str, open_file))
    for openat_file, mode in openat_map.items():
        mode_str = get_mode_str(mode)
        width = max_mode_len - len(mode_str)
        print("  %*s%s    %s" % (width, "", mode_str, openat_file))
    for fopen_file, mode_str in fopen_map.items():
        width = max_mode_len - len(mode_str)
        print("  %*s%s    %s" % (width, "", mode_str, fopen_file))
    print("")

def get_mode_str(mode):
    mode_str = uft_open_mode[mode & UFT_OPEN_MODE_MASK]

    for key, value in uft_open_flag.items():
        if mode & uft_open_flag[key] > 0:
            if mode_str == "":
                mode_str = key
            else:
                mode_str += "|" + key
    return mode_str
