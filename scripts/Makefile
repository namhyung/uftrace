srcdir = $(CURDIR)/..
incdir = $(srcdir)/include

CC  := gcc
CXX := g++
CFLAGS   := -fPIC -shared -g -I$(incdir)
CXXFLAGS := $(CFLAGS)

CC	= gcc
SRCS	= simple.c info.c count.c dump.c simple.cpp
CSO     = $(SRCS:%.c=%_c.so)
CPPSO   = $(SRCS:%.cpp=%_cpp.so)

all: $(CSO) $(CPPSO)

%_c.so: %.c
	$(CC) $(CFLAGS) -o $@ $<

%_cpp.so: %.cpp
	$(CC) $(CXXFLAGS) -o $@ $<

clean:
	rm –f *.so
