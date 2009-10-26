VPATH=../../source/extensions/stdapi
CFLAGS= -fPIC -Os -I../../source/common -I../../source/openssl/include
CFLAGS+= -I../../source/ulibc
CFLAGS+= -I../../source/extensions/stdapi/server
CFLAGS+= -D_UNIX -nostdinc -fPIC -DPIC -g -Wall
LDFLAGS= -fPIC -Bshareable 

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
else
	OS=$(OSNAME)
	CFLAGS+= -fno-stack-protector -D__linux__
endif

objects = server/general.o server/stdapi.o server/fs/dir.o server/fs/file.o \
	server/fs/fs_util.o \
	server/net/socket/tcp.o
#	server/net/config/interface.o
#	server/net/config/route.o \


all: ext_server_stdapi.so


ext_server_stdapi.so: $(objects)
	$(LD) $(LDFLAGS) -o $@ $(objects)


.PHONY: clean
clean:
	rm -f *.o *.so *~; rm -f $(objects)
