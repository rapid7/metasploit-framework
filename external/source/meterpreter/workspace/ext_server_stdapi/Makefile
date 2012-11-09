VPATH=../../source/extensions/stdapi

OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server

CFLAGS=-fno-stack-protector -nostdinc -nostdlib -fPIC -DPIC -Wall
CFLAGS+=-D_UNIX -D__linux__
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL}
CFLAGS+= -I ../../source/bionic/libc/include -I ../../source/bionic/libc/kernel/common/linux/ -I ../../source/bionic/libc/kernel/common/ -I ../../source/bionic/libc/arch-x86/include/
CFLAGS+= -I ../../source/bionic/libc/kernel/arch-x86/
CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t"
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -lgcc -L../../source/bionic/compiled
CFLAGS+= -I../../source/extensions/stdapi/server -lc -lsupport -lmetsrv_main

CFLAGS+= -march=i386 -m32 -Os

#LDFLAGS= -fPIC -Bshareable -lc

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
else
	OS=$(OSNAME)
	CFLAGS+= -fno-stack-protector -D__linux__
endif

objects = \
	server/fs/dir.o \
	server/fs/file.o \
	server/fs/fs_util.o \
	server/general.o \
	server/net/config/interface.o \
	server/net/config/route.o \
	server/net/config/arp.o \
	server/net/config/netstat.o \
	server/net/socket/tcp.o \
	server/net/socket/tcp_server.o \
	server/net/socket/udp.o \
	server/stdapi.o \
	server/sys/config/config.o \
	server/sys/process/linux-in-mem-exe.o \
	server/sys/process/process.o \
	server/sys/process/ps.o \

all: ext_server_stdapi.so

output_dirs:
	mkdir -p server/fs
	mkdir -p server/net/config
	mkdir -p server/net/socket
	mkdir -p server/sys/config
	mkdir -p server/sys/process

debug: CFLAGS+=-ggdb
debug: all

ext_server_stdapi.so: output_dirs $(objects)
	$(CC) -Wl,--hash-style=sysv -shared $(CFLAGS) $(objects) -lcrypto -o $@


.PHONY: clean debug output_dirs
clean:
	rm -f *.o *.so *~
	rm -f $(objects) ext_server_stdapi.so

