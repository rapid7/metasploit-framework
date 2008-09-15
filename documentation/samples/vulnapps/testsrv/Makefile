
SOURCES=testsrv.c
OPTIONS=-fno-stack-protector -Wa,--execstack -Wl,-z,execstack

default:x86_32 x86_64
all:	x86_32 x86_64

x86_32:
	gcc -m32 ${OPTIONS} -o testsrv32 ${SOURCES}
x86_64:
	gcc -m64 ${OPTIONS} -o testsrv64 ${SOURCES}

clean:
	rm testsrv32
	rm testsrv64


