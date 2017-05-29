file uftrace
set breakpoint pending on

b command_record
commands
  set follow-fork-mode child
  b main
  continue
end

r record -L. -d xxx tests/t-abc
 
