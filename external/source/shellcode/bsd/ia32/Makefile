ASM=nasm
STAGERS=stager_sock_bind stager_sock_bind_ipv6 stager_sock_find stager_sock_reverse stager_sock_reverse_ipv6
STAGES=stage_tcp_shell
SINGLE=single_bind_tcp_shell single_exec single_find_tcp_shell single_reverse_libinject single_reverse_tcp_shell single_findsock single_reverse_tcp_shell_ipv6 single_bind_tcp_shell_ipv6
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASMBSD}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
