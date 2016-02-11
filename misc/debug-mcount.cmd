file ftrace
set breakpoint pending on

b command_record
commands
  set follow-fork-mode child
  b main
  continue
end

r record -L. tests/t-malloc
 
