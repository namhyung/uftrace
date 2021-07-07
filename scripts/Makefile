srcdir = $(CURDIR)/..
incdir = $(srcdir)/include

CC := gcc
CFLAGS := -fPIC -shared -g -I$(incdir)

script:
	$(CC) $(CFLAGS) -o simple.so simple.c
	$(CC) $(CFLAGS) -o info.so info.c
	$(CC) $(CFLAGS) -o count.so count.c
	$(CC) $(CFLAGS) -o dump.so dump.c

clean:
	rm -f *.so
