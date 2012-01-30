
CFLAGS=-I${PWD}/hack
CFLAGS+= -I ../../bionic/libc/include -I ../../bionic/libc/kernel/common/linux/ -I ../../bionic/libc/kernel/common/ -I ../../bionic/libc/arch-x86/include/
CFLAGS+= -I ../../bionic/libc/kernel/arch-x86/ -I../../source/server/elf/headers -I../../bionic/libc/private -fPIC -DPIC
CFLAGS+= -nostdinc -nostdlib -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -DANDROID_X86_LINKER
CFLAGS+= -ggdb
CFLAGS+= -DMETSRV_RTLD -D_BYTE_ORDER=_LITTLE_ENDIAN

CFLAGS+= -march=i386

OBJ=msflinker.o basic_libc.o syscall.o linker_format.o dlfcn.o zlib.o metsrv_rtld.o

all: msflinker msflinker.bin rtldtest

msflinker: $(OBJ)
	gcc -Wl,-script=script -Wl,--hash-style=sysv $(CFLAGS) -o msflinker $(OBJ) -lgcc

msflinker.bin: msflinker elf2bin.c
	gcc -o elf2bin elf2bin.c
	./elf2bin msflinker msflinker.bin

libc.h: ../../bionic/compiled/libc.so
	strip --strip-debug ../../bionic/compiled/libc.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libc.so libc

libm.h: ../../bionic/compiled/libm.so
	strip --strip-debug ../../bionic/compiled/libm.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libm.so libm

libcrypto.h: ../../bionic/compiled/libcrypto.so
	strip --strip-debug ../../bionic/compiled/libcrypto.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libcrypto.so libcrypto

libssl.h: ../../bionic/compiled/libssl.so
	strip --strip-debug ../../bionic/compiled/libssl.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libssl.so libssl

libsupport.h: ../../bionic/compiled/libsupport.so
	strip --strip-debug ../../bionic/compiled/libsupport.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libsupport.so libsupport

libmetsrv_main.h: ../../bionic/compiled/libmetsrv_main.so
	strip --strip-debug ../../bionic/compiled/libmetsrv_main.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libmetsrv_main.so libmetsrv_main

libpcap.h: ../../bionic/compiled/libpcap.so
	strip --strip-debug ../../bionic/compiled/libpcap.so
	perl ../../../tools/so2h.pl ../../bionic/compiled/libpcap.so libpcap

metsrv_rtld.o: libc.h libm.h libcrypto.h libssl.h libmetsrv_main.h libsupport.h libpcap.h

rtldtest: rtldtest.c msflinker
	gcc -o rtldtest rtldtest.c -DEP=`objdump -f msflinker | grep start | awk '{ print $$3 }'`

.s.o:
	gcc $(CFLAGS) -c $<

.c.o:
	gcc $(CFLAGS) -c $<

clean:
	rm -f libmetsrv_main.h  libssl.h  libcrypto.h  libm.h  libc.h libsupport.h 
	rm -f *.o 
	rm -f msflinker msflinker.so
	rm -f rtldtest elf2bin
