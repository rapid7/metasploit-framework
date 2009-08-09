.SUFFIXES: .S .c

SOURCEPATH=../../source/ulibc
SSLPATH=../../source/openssl/include
STDLIBPATH=../../source/ulibc/stdlib
COMMONPATH=../../source/common

CFLAGS= -D_UNIX -I$(SOURCEPATH) -DNO_TLS -DPIC -I$(COMMONPATH) -I$(SSLPATH) -I$(STDLIBPATH)
CFLAGS+= -g -fPIC -Os -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1

CPPFLAGS= -I$(SOURCEPATH) -DPIC

CC=gcc
AR=ar
RM=rm

libc_objects = table.o none.o localeconv.o lmonetary.o lnumeric.o \
	wcrtomb.o wcsrtombs.o \
	findfp.o stdio.o fflush.o printf.o vfprintf.o atexit.o getenv.o \
	strtol.o reallocf.o __error.o \
	wsetup.o makebuf.o fwalk.o _flock_stub.o fvwrite.o qsort.o \
	exit.o bcopy.o memmove.o stpcpy.o memchr.o strchr.o \
	strerror.o strlcpy.o strncpy.o strlcat.o strncat.o \
	inet_addr.o \
	_thread_init.o time.o isatty.o termios.o errlst.o sigsetops.o \
	malloc.o syscalls.o ulibc.o 

####### check platform
OSNAME= $(shell uname -s)
ARCH= $(shell uname -m)

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
	libc_objects+= cerror.o
else
	CFLAGS+= -fno-stack-protector -D__linux__
	CFLAGS+=  -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1 
	OS=$(OSNAME)
#	requires tls - which we don't have
#	libc_objects+= errno.o
endif

BASEVPATH=../../source/ulibc:../../source/ulibc/arch/posix:../../source/ulibc/locale:../../source/ulibc/stdio:../../source/ulibc/stdlib:../../source/ulibc/gen:../../source/ulibc/inet:../../source/ulibc/string:
OSVPATH= ../../source/ulibc/arch/$(OS)
ARCHVPATH= $(OSVPATH)/$(ARCH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

CFLAGS+= -I$(ARCHVPATH)
CPPFLAGS+= -I$(ARCHVPATH)

all: libuc.so libuc.a

libuc.so: $(library_headers) $(libc_objects)
	$(LD) -Bshareable -o $@ $(libc_objects)

libuc.a: $(libc_objects)
	$(AR) rc $@ $(libc_objects) 

clean:
	$(RM) -f *.o *.a *.so

.PHONY: clean

