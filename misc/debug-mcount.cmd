file ftrace
set follow-fork-mode child
set breakpoint pending on
#b main
#b __monstartup
b plt_hooker
r record -L. tests/t-abc
 
