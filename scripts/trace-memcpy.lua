--
-- trace-memcpy.lua
--
-- uftrace-option: --nest-libcall -T memcpy@filter,arg3
--
--   void *memcpy(void *dest, const void *src, size_t n);
--

-- Only "memcpy" calls this script and other functions never.
UFTRACE_FUNCS = { 'memcpy' }

count = 0
total_bytes = 0

function uftrace_begin(ctx)
end

function uftrace_entry(ctx)
    count = count + 1
    if ctx['args'] ~= nil then
        total_bytes = total_bytes + ctx['args'][1]
    end
end

function uftrace_exit(ctx)
end

function uftrace_end()
    print(count .. ' times memcpy called')
    print(total_bytes .. ' bytes copied')
end
