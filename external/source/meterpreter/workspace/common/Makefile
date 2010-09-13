.SUFFIXES: .S .c

SOURCEPATH=../../source/common
SSLPATH=../../source/openssl/include
MALLOC_PATH=../../source/common/malloc
XOR_PATH=../../source/common/crypto
STDLIBPATH=../../source/common/stdlib
ZLIB_PATH=../../source/common/zlib


CFLAGS=-nostdinc -nostdlib
CFLAGS+= -I ../../source/bionic/libc/include -I ../../source/bionic/libc/kernel/common/linux/ -I ../../source/bionic/libc/kernel/common/ 
CFLAGS+= -I ../../source/bionic/libc/arch-x86/include/
CFLAGS+= -I ../../source/bionic/libc/kernel/arch-x86/ 
CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -lgcc -L../../source/bionic/compiled

CFLAGS+= -D_UNIX -I$(SOURCEPATH) -I$(MALLOC_PATH) -I$(XOR_PATH) -DMALLOC_PRODUCTION -DPIC -I$(SSLPATH) -I$(STDLIBPATH) -I$(ZLIB_PATH)
CFLAGS+= -g -fPIC -Os -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1

CPPFLAGS= -I$(SOURCEPATH) -DPIC

CC=gcc
AR=ar
RM=rm

objects = args.o base.o base_dispatch.o base_dispatch_common.o buffer.o \
	channel.o common.o core.o list.o remote.o thread.o xor.o zlib.o 



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

BASEVPATH=../../source/common:../../source/common/crypto:../../source/common/arch/posix:../../source/common/zlib:
OSVPATH= ../../source/common/arch/$(OS)
ARCHVPATH= $(OSVPATH)/$(ARCH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

CFLAGS+= -I$(ARCHVPATH)
CPPFLAGS+= -I$(ARCHVPATH)

all: libsupport.so

libsupport.so: $(objects)
	$(CC) $(CFLAGS) -shared -o $@ $(objects)  -lc -lssl -lcrypto

clean:
	$(RM) -f *.o *.a *.so zlib/zlib.o

.PHONY: clean

