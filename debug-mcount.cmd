file ftrace
set follow-fork-mode child
set breakpoint pending on
b main
#b __monstartup
#b __gnu_mcount_nc
r record --use-pipe -L. tests/t-abc
 
