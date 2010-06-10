.SUFFIXES: .S .c

SOURCEPATH=../../source/common
SSLPATH=../../source/openssl/include
MALLOC_PATH=../../source/common/malloc
XOR_PATH=../../source/common/crypto
STDLIBPATH=../../source/common/stdlib
ZLIB_PATH=../../source/common/zlib

CFLAGS= -D_UNIX -I$(SOURCEPATH) -I$(MALLOC_PATH) -I$(XOR_PATH) -DMALLOC_PRODUCTION -DNO_TLS -DPIC -I$(SSLPATH) -I$(STDLIBPATH) -I$(ZLIB_PATH)
CFLAGS+= -g -fPIC -Os -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1

CPPFLAGS= -I$(SOURCEPATH) -DPIC

CC=gcc
AR=ar
RM=rm

objects = args.o base.o base_dispatch.o base_dispatch_common.o buffer.o \
	channel.o common.o core.o list.o remote.o scheduler.o thread.o xor.o zlib/zlib.o



####### check platform
OSNAME= $(shell uname -s)
ARCH= $(shell uname -m | sed 's/i[456]86/i386/g')

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

BASEVPATH=../../source/common:../../source/common/crypto:../../source/common/arch/posix:
OSVPATH= ../../source/common/arch/$(OS)
ARCHVPATH= $(OSVPATH)/$(ARCH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

CFLAGS+= -I$(ARCHVPATH)
CPPFLAGS+= -I$(ARCHVPATH)

all: libsupport.a

libsupport.a: $(objects)
	$(AR) rc $@ $(objects) 

clean:
	$(RM) -f *.o *.a *.so

.PHONY: clean

