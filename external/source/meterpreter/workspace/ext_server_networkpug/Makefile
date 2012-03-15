VPATH=../../source/extensions/networkpug

OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server
PCAP=../../source/libpcap
LIBC=../../source/bionic/libc

CFLAGS=-nostdinc -nostdlib -fPIC -DPIC -Wall
CFLAGS+=-D_UNIX -D__linux__
CFLAGS+=-I$(COMMON) -I$(SERVER) -I$(OPENSSL) -I$(PCAP)
CFLAGS+= -I$(LIBC)/include -I$(LIBC)/kernel/common/linux/ -I$(LIBC)/kernel/common/ -I$(LIBC)/arch-x86/include/
CFLAGS+= -I$(LIBC)/kernel/arch-x86/
CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t"
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -lgcc -L../../source/bionic/compiled
CFLAGS+= -I../../source/extensions/networkpug -lc -lpcap -lsupport -lmetsrv_main

CFLAGS+= -march=i386 -m32 -Os

#LDFLAGS= -fPIC -Bshareable -lc

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
else
	OS=$(OSNAME)
	CFLAGS+= -fno-stack-protector -D__linux__
endif

objects = networkpug.o

all: ext_server_networkpug.so

debug: CFLAGS+= -ggdb
debug: all

ext_server_networkpug.so: $(objects)
	$(CC) -Wl,--hash-style=sysv -shared $(CFLAGS) $(objects) -o $@


.PHONY: clean debug
clean:
	rm -f *.o *.so *~; rm -f $(objects)
