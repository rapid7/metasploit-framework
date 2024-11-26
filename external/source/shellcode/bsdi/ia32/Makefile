ASM=nasm
STAGERS=stager_sock_bind stager_sock_find stager_sock_reverse 
STAGES=stage_tcp_shell
SINGLE=single_bind_tcp_shell single_find_tcp_shell single_reverse_tcp_shell
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASM}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
