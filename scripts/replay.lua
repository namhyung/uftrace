function uftrace_begin(ctx)
    print('# DURATION     TID     FUNCTION')
end

function uftrace_entry(ctx)
    local _tid = ctx['tid']
    local _depth = ctx['depth']
    local _symname = ctx['name']

    local indent = _depth * 2
    local space = string.rep(' ', indent)

    local buf = string.format(' %10s [%6d] | %s%s() {', '', _tid, space, _symname)
    print(buf)
end

function uftrace_exit(ctx)
    local _tid = ctx['tid']
    local _depth = ctx['depth']
    local _symname = ctx['name']
    local _duration = ctx['duration']

    local indent = _depth * 2
    local space = string.rep(' ', indent)

    local time_and_unit = get_time_and_unit(_duration)
    local time = time_and_unit[1]
    local unit = time_and_unit[2]
    local buf = string.format(' %7.3f %s [%6d] | %s}', time, unit, _tid, space)
    local buf = string.format('%s /* %s */', buf, _symname)
    print(buf)
end

function uftrace_end()
end

function get_time_and_unit(duration)
    local duration = duration
    local time_unit = ''
    local divider

    if duration < 100 then
        divider = 1
        time_unit = 'ns'
    elseif duration < 1000000 then
        divider = 1000
        time_unit = 'us'
    elseif duration < 1000000000 then
        divider = 1000000
        time_unit = 'ms'
    else
        divider = 1000000000
        time_unit = ' s'
    end

    return {duration / divider, time_unit}
end
