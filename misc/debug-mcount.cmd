file uftrace
set breakpoint pending on

#b command_record
catch exec
commands
#  set follow-fork-mode child
  b main
  continue
end

r record -L. -d xxx --keep-pid --force tests/t-abc
 
