file ftrace
set follow-fork-mode child
set breakpoint pending on
#b main
b __monstartup
r record -d --plthook tests/t-arg 1 2 3
 
