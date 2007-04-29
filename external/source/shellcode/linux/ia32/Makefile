ASM=nasm
STAGERS=stager_sock_bind stager_sock_bind_udp stager_sock_bind_icmp \
        stager_egghunt stager_sock_find stager_sock_reverse \
        stager_sock_reverse_icmp stager_sock_reverse_udp \
		  stager_sock_reverse_udp_dns
STAGES=stage_tcp_shell stage_udp_shell
SINGLE=single_adduser single_bind_tcp_shell single_find_tcp_shell \
       single_reverse_tcp_shell single_reverse_udp_shell single_exec
OBJS=${STAGERS} ${STAGES} ${SINGLE}

include ../../Makefile.incl

all: 
	@for i in ${OBJS}; ${BUILDASM}; done

clean:
	rm -f *.o *.hex ${OBJS} *.disasm
