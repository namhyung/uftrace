#!/usr/bin/env python

# uftrace-option: --force --nest-libcall -A malloc@arg1 -R malloc@retval -A free@arg1 -A calloc@arg1,arg2 -R calloc@retval -A realloc@arg1,arg2 -R realloc@retval -A memalign@arg1,arg2 -R memalign@retval -A malloc@libstdc++,arg1 -R malloc@libstdc++,retval -A free@libstdc++,arg1 -A calloc@libstdc++,arg1,arg2 -R calloc@libstdc++,retval -A realloc@libstdc++,arg1,arg2 -R realloc@libstdc++,retval -A memalign@libstdc++,arg1,arg2 -R memalign@libstdc++,retval

import sys

UFTRACE_FUNCS = [ "malloc", "free", "calloc", "realloc" ]

current = 0
size = 0
addr = 0
begin_timestamp = 0
nmemb = 0

malloc_map   = {}   # { key: address, value: memory size allocated at this address }
timeline_arr = []   # elapsed time
mem_usage_arr = []  # total memory usage in bytes

def uftrace_begin():
    print("")
    print("   ELAPSED TIME   FUNCTION                    ADDRESS           ALLOCATED BYTES")
    print("  ==============================================================================")

def uftrace_entry(ctx):
    global current
    global size
    global addr
    global malloc_map
    global timeline_arr
    global mem_usage_arr
    global begin_timestamp
    global nmemb

    _name = ctx["name"]
    _timestamp = ctx["timestamp"]

    if begin_timestamp is 0:
        begin_timestamp = _timestamp

    if _name == "malloc":
        size = ctx["args"][0]
    elif _name == "calloc":
        # calloc(size_t nmemb, size_t size)
        nmemb = ctx["args"][0]
        size  = ctx["args"][1]
    elif _name == "realloc":
        # void *realloc(void *ptr, size_t size);
        addr = ctx["args"][0]
        size = ctx["args"][1]
    elif _name == "free":
        # void free(void *ptr);
        addr = ctx["args"][0]
        free_call = "free(%#x)" % addr
        if malloc_map.has_key(hex(addr)):
            free_size = malloc_map[hex(addr)]
            current -= malloc_map[hex(addr)]
            del malloc_map[hex(addr)]
        else:
            if addr == 0:
                free_size = 0
            else:
                print("")
                print("  %13s   INVALID ADDRESS FREE" % "")
                free_size = "xxx"
        elapsed_time = _timestamp - begin_timestamp
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        print("  %13d : %-25s   %-14s    %d (-%s)" % (elapsed_time, free_call, "", current, free_size))

def uftrace_exit(ctx):
    global current
    global size
    global addr
    global malloc_map
    global timeline_arr
    global mem_usage_arr
    global begin_timestamp

    _name = ctx["name"]
    _timestamp = ctx["timestamp"]

    if _name == "malloc":
        # void *malloc(size_t size);
        addr = ctx["retval"]
        malloc_map[hex(addr)] = size
        current += size
        elapsed_time = _timestamp - begin_timestamp
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        malloc_call = "malloc(%d)" % size
        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, malloc_call, addr, current))
    elif _name == "calloc":
        # void *calloc(size_t nmemb, size_t size);
        addr = ctx["retval"]
        malloc_map[hex(addr)] = nmemb * size
        current += nmemb * size
        elapsed_time = _timestamp - begin_timestamp
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        calloc_call = "calloc(%d, %d)" % (nmemb, size)
        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, calloc_call, addr, current))
    elif _name == "realloc":
        # void *realloc(void *ptr, size_t size);
        current -= malloc_map[hex(addr)]
        del malloc_map[hex(addr)]
        realloc_call = "realloc(%#x, %d)" % (addr, size)

        addr = ctx["retval"]
        malloc_map[hex(addr)] = size
        current += size
        elapsed_time = _timestamp - begin_timestamp
        timeline_arr.append(elapsed_time)
        mem_usage_arr.append(current)
        print("  %13d : %-25s = %#-14x    %d" % (elapsed_time, realloc_call, addr, current))

def uftrace_end():
    global current
    global malloc_map
    print("  =========================================================================\n")
    if current is not 0:
        print("")
        print("  * %d bytes are not free-ed in %d objects" % (current, len(malloc_map)))
        print("")
        print("    NON-FREE ADDRESS          SIZE (bytes)")
        print("  =========================================================================")
        for key, value in malloc_map.items():
            print("     %#15s          %d" % (key[:-1], value))
        print("  =========================================================================")
        print("")

