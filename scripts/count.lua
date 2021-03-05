local count = 0

function uftrace_begin(ctx)
end

function uftrace_entry(ctx)
    count = count + 1
end

function uftrace_exit(ctx)
end

function uftrace_end()
    print(count)
end
