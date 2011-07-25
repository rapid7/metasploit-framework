VPATH=../../source/extensions/networkpug

OPENSSL=${PWD}/../../source/openssl/include
COMMON=${PWD}/../../source/common
SERVER=../../source/server
PCAP=../../source/libpcap

CFLAGS=-fno-stack-protector -nostdinc -nostdlib -fPIC -DPIC -g -Wall
CFLAGS+=-D_UNIX -D__linux__
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL} -I${PCAP}
CFLAGS+= -I ../../source/bionic/libc/include -I ../../source/bionic/libc/kernel/common/linux/ -I ../../source/bionic/libc/kernel/common/ -I ../../source/bionic/libc/arch-x86/include/
CFLAGS+= -I ../../source/bionic/libc/kernel/arch-x86/
CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t"
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -lgcc -L../../source/bionic/compiled -gstabs+
CFLAGS+= -fPIC -Os 
CFLAGS+= -I../../source/extensions/networkpug -lc -lpcap -lsupport -lmetsrv_main

#LDFLAGS= -fPIC -Bshareable -lc

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
else
	OS=$(OSNAME)
	CFLAGS+= -fno-stack-protector -D__linux__
endif

objects = networkpug.o

all: ext_server_networkpug.so


ext_server_networkpug.so: $(objects)
	$(CC) -Wl,--hash-style=sysv -shared $(CFLAGS) $(objects) -o $@


.PHONY: clean
clean:
	rm -f *.o *.so *~; rm -f $(objects)
