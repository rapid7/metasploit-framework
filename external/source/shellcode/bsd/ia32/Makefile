ASM=nasm
STAGERS=stager_sock_bind stager_sock_find stager_sock_reverse
STAGES=stage_tcp_shell
SINGLE=single_bind_tcp_shell single_exec single_find_tcp_shell single_reverse_libinject single_reverse_tcp_shell single_findsock
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASMBSD}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
