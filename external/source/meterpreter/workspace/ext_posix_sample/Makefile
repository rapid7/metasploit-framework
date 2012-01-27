VPATH=../../source/extensions/posix_sample

OPENSSL=../../source/openssl/include
COMMON=../../source/common
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
CFLAGS+= -I../../source/extensions/stdapi/server -lc -lsupport

CFLAGS+= -march=i386 -m32

objects = test.o

all: posix_sample.so

posix_sample.so: test.o
	gcc -shared $(CFLAGS) -o $@ $(objects)

# And, once done:
# copy posix_sample.so to data/meterpreter/ext_server_posix_sample.lso and "use posix_sample"

.PHONY: clean
clean:
	rm -f *.o *.so *~
