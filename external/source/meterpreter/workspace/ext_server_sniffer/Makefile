VPATH=../../source/extensions/sniffer

OPENSSL=../../source/openssl/include
COMMON=../../source/common
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
CFLAGS+= -I.

objects = sniffer.o

all: ext_server_sniffer.so


ext_server_sniffer.so: $(objects)
	$(CC) -shared $(CFLAGS) $(objects) -lpcap -o $@

.PHONY: clean
clean:
	rm -f *.o *.so *~; rm -f $(objects)
