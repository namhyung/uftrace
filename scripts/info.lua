function uftrace_begin(ctx)
    print(ctx['record'])
    print(ctx['version'])
    io.write('(')
    for _, cmd in ipairs(ctx['cmds']) do
        io.write("'" .. cmd .. "', ")
    end
    print(')')
end

function uftrace_entry(ctx)
end

function uftrace_exit(ctx)
end
