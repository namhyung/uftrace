--
-- strings.lua - print the unique strings of runtime function arguments and return values.
--
-- uftrace-option: --nest-libcall --auto-args
--

local strset = {}

function uftrace_entry(ctx)
    if ctx['args'] ~= nil then
        for i, arg in ipairs(ctx['args']) do
            if type(arg) == 'string' then
                arg = string.gsub(arg, '^%s+', '')
                arg = string.gsub(arg, '%s+$', '')
                if arg ~= '' then
                    strset[arg] = true
                end
            end
        end
    end
end

function uftrace_exit(ctx)
    if ctx['retval'] ~= nil then
        local ret = ctx['retval'] 
        if type(ctx['retval']) == 'string' then
            ret = string.gsub(ret, '^%s+', '')
            ret = string.gsub(ret, '%s+$', '')
            if ret ~= '' then
                strset[ret] = true
            end
        end
    end
end

function uftrace_end()
    for strval, _ in pairs(strset) do
        print('"' .. strval .. '"')
        print("---")
    end
end
