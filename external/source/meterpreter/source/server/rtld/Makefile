CFLAGS=-I${PWD}/hack
CFLAGS+= -I /opt/bionic/libc/include -I /opt/bionic/libc/kernel/common/linux/ -I /opt/bionic/libc/kernel/common/ -I /opt/bionic/libc/arch-x86/include/
CFLAGS+= -I /opt/bionic/libc/kernel/arch-x86/ -I../../source/server/elf/headers -I/opt/bionic/libc/private -fPIC -DPIC
CFLAGS+= -nostdinc -nostdlib -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -DANDROID_X86_LINKER -ggdb

OBJ=msflinker.o basic_libc.o syscall.o linker_format.o dlfcn.o zlib.o metsrv_rtld.o

all: $(OBJ) 
	gcc $(CFLAGS) -shared -o msflinker.so ${OBJ}

libc.h: ../../bionic/compiled/libc.so
	../../../tools/so2h.pl ../../bionic/compiled/libc.so libc

libm.h: ../../bionic/compiled/libm.so
	../../../tools/so2h.pl ../../bionic/compiled/libm.so libm

libcrypto.h: ../../bionic/compiled/libcrypto.so
	../../../tools/so2h.pl ../../bionic/compiled/libcrypto.so libcrypto

libssl.h: ../../bionic/compiled/libssl.so
	../../../tools/so2h.pl ../../bionic/compiled/libssl.so libssl

libsupport.h: ../../bionic/compiled/libsupport.so
	../../../tools/so2h.pl ../../bionic/compiled/libsupport.so libsupport

metsrv_main.h: ../../bionic/compiled/metsrv_main
	../../../tools/so2h.pl ../../bionic/compiled/metsrv_main metsrv_main

metsrv_rtld.o: libc.h libm.h libcrypto.h libssl.h metsrv_main.h libsupport.h

test: $(OBJ) 
	gcc $(CFLAGS) -o msflinker $(OBJ) -lgcc 

.s.o:
	gcc $(CFLAGS) -c $<

.c.o:
	gcc $(CFLAGS) -c $<

clean:
	rm  metsrv_main.h  libssl.h  libcrypto.h  libm.h  libc.h
	rm *.o 
	rm msflinker msflinker.so

