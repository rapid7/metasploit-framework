PWD=`pwd`/
BASEVPATH=../../source/server:../../source/server/posix/
OPENSSL=${PWD}../../source/openssl/include
COMMON=${PWD}../../source/common
SERVER=../../source/server

CFLAGS=-fno-stack-protector -nostdinc -nostdlib 
CFLAGS+=-D_UNIX -D__linux__ 
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL}
CFLAGS+= -I ../../source/bionic/libc/include -I ../../source/bionic/libc/kernel/common/linux/ -I ../../source/bionic/libc/kernel/common/ -I ../../source/bionic/libc/arch-x86/include/
CFLAGS+= -I ../../source/bionic/libc/kernel/arch-x86/ 
CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" 
CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS+= -lgcc -L../../source/bionic/compiled -gstabs+

OS=posix
OSVPATH=../../source/common/arch/$(OS)
ARCHVPATH=$(OSVPATH)/$(RARCH):$(ELFARCHPATH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

objects= metsrv.o scheduler.o 
objects+= server_setup.o remote_dispatch_common.o remote_dispatch.o # metsrv_main.o 

all:  metsrv_main 

metsrv_main: $(objects)
	$(CC) -pie $(CFLAGS) -o $@ $(objects) -export-dynamic -lc -lcrypto -lssl -lgcc -ldl -lsupport

clean:
	@echo "ARCHVPATH= " $(ARCHVPATH) " VPATH= " $(VPATH)
	$(RM) -f *.o *.h *.so *.gz *~ *.a metsrv_main 

.PHONY: clean
