#
# Makefile for msflorcon
#

NAME=msflorcon-$(shell ruby -e 'puts RUBY_PLATFORM')
CFLAGS  := -I. -I/usr/include -I/usr/local/include
LDFLAGS := -L. -lorcon

%.o:
	$(CC) -fPIC -c $(CFLAGS) *.c
	
shared: %.o
	$(CC) -fPIC -shared -o $(NAME).so *.o $(LDFLAGS)
	
all: shared
	strip *.so

clean:
	rm -f *.o core a.out *.so
