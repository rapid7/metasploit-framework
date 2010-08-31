VPATH=../../source/extensions/stdapi

OPENSSL=${PWD}/../../source/openssl/include
COMMON=${PWD}/../../source/common
SERVER=../../source/server

CFLAGS=-fno-stack-protector -nostdinc -nostdlib -fPIC -DPIC -g -Wall
CFLAGS+=-D_UNIX -D__linux__
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL}
CFLAGS+= -I ../../source/bionic/libc/include -I ../../source/bionic/libc/kernel/common/linux/ -I ../../source/bionic/libc/kernel/common/ -I ../../source/bionic/libc/arch-x86/include/
CFLAGS+= -I ../../source/bionic/libc/kernel/arch-x86/
CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t"
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -lgcc -L../../source/bionic/compiled -gstabs+
CFLAGS+= -fPIC -Os 
CFLAGS+= -I../../source/extensions/stdapi/server -lc -lsupport -lmetsrv_main

#LDFLAGS= -fPIC -Bshareable -lc

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
else
	OS=$(OSNAME)
	CFLAGS+= -fno-stack-protector -D__linux__
endif

objects = server/general.o server/stdapi.o server/fs/dir.o server/fs/file.o \
	server/fs/fs_util.o \
	server/net/socket/tcp.o server/net/socket/tcp_server.o server/net/socket/udp.o \
	server/sys/config/config.o server/sys/process/process.o
	#server/net/config/interface.o \
	#server/net/config/route.o \


all: ext_server_stdapi.so


ext_server_stdapi.so: $(objects)
	$(CC) -shared $(CFLAGS) -o $@ $(objects) 


.PHONY: clean
clean:
	rm -f *.o *.so *~; rm -f $(objects)
