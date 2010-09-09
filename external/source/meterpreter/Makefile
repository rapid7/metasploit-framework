# PKS, I suck at Makefile's.  Given that this compiles POSIX meterpreter and
# associated stuff (openssl, libpcap, etc) this is going to get very messy,
# very quickly.

all: external/source/meterpreter/source/bionic/compiled/libc.so external/source/meterpreter/source/bionic/compiled/libm.so external/source/meterpreter/source/bionic/compiled/libdl.so external/source/meterpreter/source/bionic/compiled/libcrypto.so external/source/meterpreter/source/bionic/compiled/libssl.so external/source/meterpreter/source/bionic/compiled/libsupport.so external/source/meterpreter/source/bionic/compiled/libmetsrv_main.so data/meterpreter/msflinker_linux_x86.bin data/meterpreter/ext_server_stdapi.lso

external/source/meterpreter/source/bionic/compiled/libc.so: external/source/meterpreter/source/bionic/compiled
	(cd external/source/meterpreter/source/bionic/libc && ARCH=x86 TOP=${PWD} jam && cd out/x86/ && sh make.sh && [ -f libbionic.so ] )
	cp external/source/meterpreter/source/bionic/libc/out/x86/libbionic.so external/source/meterpreter/source/bionic/compiled/libc.so

external/source/meterpreter/source/bionic/compiled:
	mkdir external/source/meterpreter/source/bionic/compiled/

external/source/meterpreter/source/bionic/compiled/libm.so:
	(cd external/source/meterpreter/source/bionic/libm && make -f msfMakefile && [ -f libm.so ])
	cp external/source/meterpreter/source/bionic/libm/libm.so external/source/meterpreter/source/bionic/compiled/libm.so

external/source/meterpreter/source/bionic/compiled/libdl.so:
	(cd external/source/meterpreter/source/bionic/libdl && make && [ -f libdl.so ])
	cp external/source/meterpreter/source/bionic/libdl/libdl.so external/source/meterpreter/source/bionic/compiled/libdl.so

external/source/meterpreter/source/bionic/compiled/libcrypto.so: tmp/openssl-0.9.8o/libssl.so
	cp tmp/openssl-0.9.8o/libcrypto.so external/source/meterpreter/source/bionic/compiled/libcrypto.so 

external/source/meterpreter/source/bionic/compiled/libssl.so: tmp/openssl-0.9.8o/libssl.so
	cp tmp/openssl-0.9.8o/libssl.so external/source/meterpreter/source/bionic/compiled/libssl.so

tmp:
	[ ! -d tmp ] && mkdir tmp 

tmp/openssl-0.9.8o.tar.gz: tmp
	[ ! -f tmp/openssl-0.9.8o.tar.gz ] && wget -O tmp/openssl-0.9.8o.tar.gz http://openssl.org/source/openssl-0.9.8o.tar.gz


tmp/openssl-0.9.8o:
	tar -C tmp/ -xzf tmp/openssl-0.9.8o.tar.gz

tmp/openssl-0.9.8o/libssl.so:
	(cd tmp/openssl-0.9.8o && ./Configure threads no-zlib no-krb5 386 --prefix=/tmp/out linux-elf shared)
	(cd tmp/openssl-0.9.8o && make CC="gcc -I${PWD}/external/source/meterpreter/source/bionic/libc/include -I${PWD}/external/source/meterpreter/source/bionic/libc/kernel/common/linux/ -I${PWD}/external/source/meterpreter/source/bionic/libc/kernel/common/ -I${PWD}/external/source/meterpreter/source/bionic/libc/arch-x86/include/ -I${PWD}/external/source/meterpreter/source/bionic/libc/kernel/arch-x86/  -I${PWD}/external/source/meterpreter/source/bionic/libc/private -fPIC -DPIC -nostdinc -nostdlib -Dwchar_t='char' -fno-builtin -D_SIZE_T_DECLARED -DElf_Size='u_int32_t' -I${PWD}/external/source/meterpreter/source/bionic/libm/include  -L${PWD}/external/source/meterpreter/source/bionic/compiled  -D_BYTE_ORDER=_LITTLE_ENDIAN -lc" depend  clean all ; [ -f libssl.so.0.9.8 -a -f libcrypto.so.0.9.8 ] )

data/meterpreter/msflinker_linux_x86.bin: external/source/meterpreter/source/server/rtld/msflinker.bin
	cp external/source/meterpreter/source/server/rtld/msflinker.bin data/meterpreter/msflinker_linux_x86.bin

external/source/meterpreter/source/server/rtld/msflinker.bin:
	(cd external/source/meterpreter/source/server/rtld ; make)

external/source/meterpreter/source/bionic/compiled/libmetsrv_main.so:
	(cd external/source/meterpreter/workspace/metsrv && make)
	cp external/source/meterpreter/workspace/metsrv/libmetsrv_main.so external/source/meterpreter/source/bionic/compiled/libmetsrv_main.so 

external/source/meterpreter/source/bionic/compiled/libsupport.so:
	(cd external/source/meterpreter/workspace/common && make) 
	cp external/source/meterpreter/workspace/common/libsupport.so external/source/meterpreter/source/bionic/compiled/libsupport.so

data/meterpreter/ext_server_stdapi.lso:
	(cd external/source/meterpreter/workspace/ext_server_stdapi && make)
	cp external/source/meterpreter/workspace/ext_server_stdapi/ext_server_stdapi.so data/meterpreter/ext_server_stdapi.lso
