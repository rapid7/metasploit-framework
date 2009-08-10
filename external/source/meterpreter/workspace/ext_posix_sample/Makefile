VPATH=../../source/extensions/posix_sample
CFLAGS= -fPIC -Os -I../../source/common -I../../source/openssl/include -D_UNIX


objects = test.o

all: posix_sample.so


posix_sample.so: test.o
	$(LD) -Bshareable -o $@ $(objects)


.PHONY: clean
clean:
	rm -f *.o *.so *~