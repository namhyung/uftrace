function uftrace_begin(ctx)
    print('program begins...')
end

function uftrace_entry(ctx)
    func = ctx['name']
    print('entry : ' .. func .. '()')
end

function uftrace_exit(ctx)
    func = ctx['name']
    print('exit  : ' .. func .. '()')
end

function uftrace_end()
    print('program is finished')
end
