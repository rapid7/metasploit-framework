.SUFFIXES: .S .c

SOURCEPATH=../../source/common
SSLPATH=../../source/openssl/include
MALLOC_PATH=../../source/common/malloc
XOR_PATH=../../source/common/crypto
STDLIBPATH=../../source/common/stdlib

CFLAGS= -D_UNIX -I$(SOURCEPATH) -I$(MALLOC_PATH) -I$(XOR_PATH) -DMALLOC_PRODUCTION -DNO_TLS -DPIC -I$(SSLPATH) -I$(STDLIBPATH)
CFLAGS+= -g -fPIC -Os -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1

CPPFLAGS= -I$(SOURCEPATH) -DPIC

CC=gcc
AR=ar
RM=rm

libc_objects = table.o none.o localeconv.o lmonetary.o lnumeric.o wcrtomb.o wcsrtombs.o \
	findfp.o stdio.o fflush.o printf.o vfprintf.o atexit.o getenv.o strtol.o reallocf.o __error.o \
	wsetup.o makebuf.o fwalk.o _flock_stub.o fvwrite.o qsort.o \
	exit.o bcopy.o memmove.o stpcpy.o memchr.o strchr.o \
	strerror.o strlcpy.o strncpy.o strlcat.o strncat.o \
	inet_addr.o \
	_thread_init.o time.o isatty.o termios.o errlst.o sigsetops.o \
	malloc.o syscalls.o ulibc.o 
# ulibc.o belongs above
objects = args.o base.o base_dispatch.o base_dispatch_common.o buffer.o \
	channel.o common.o core.o remote.o scheduler.o xor.o 



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

BASEVPATH=../../source/common:../../source/common/crypto:../../source/common/arch/posix:../../source/common/locale:../../source/common/stdio:../../source/common/stdlib:../../source/common/gen:../../source/common/inet:../../source/common/string:
OSVPATH= ../../source/common/arch/$(OS)
ARCHVPATH= $(OSVPATH)/$(ARCH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

CFLAGS+= -I$(ARCHVPATH)
CPPFLAGS+= -I$(ARCHVPATH)

all: libcommon.so libsupport.a libcommon.a

libcommon.so: $(library_headers) $(libc_objects)
	$(LD) -Bshareable -o $@ $(libc_objects)

libsupport.a: $(objects)
	$(AR) rc $@ $(objects) 

libcommon.a: $(libc_objects)
	$(AR) rc $@ $(libc_objects) 

clean:
	$(RM) -f *.o *.a *.so

.PHONY: clean

