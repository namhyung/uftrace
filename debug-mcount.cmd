file ftrace
set follow-fork-mode child
set breakpoint pending on
#b main
#b __monstartup
b __gnu_mcount_nc
r record tests/arch/arm/t-thumb_O2
 
