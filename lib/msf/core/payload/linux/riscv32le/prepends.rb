#
# Linux RISC-V 32-bit prepends
#
module Msf::Payload::Linux::Riscv32le::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[PrependSetresuid PrependSetreuid PrependSetuid PrependSetresgid PrependSetregid PrependSetgid]
  end

  def appends_order
    %w[AppendExit]
  end

  def prepends_map
    {
      # setuid(0)
      'PrependSetuid' => [
        0x00000513, # li a0,0      # uid = 0
        0x09200893, # li a7,146    # __NR_setuid
        0x00000073  # ecall
      ].pack('V*'),

      # setreuid(0, 0)
      'PrependSetreuid' => [
        0x00000513, # li a0,0       # ruid = 0
        0x00000593, # li a1,0       # euid = 0
        0x09100893, # li a7,145     # __NR_setreuid
        0x00000073  # ecall
      ].pack('V*'),

      # setresuid(0, 0, 0)
      'PrependSetresuid' => [
        0x00000513, # li a0,0       # ruid = 0
        0x00000593, # li a1,0       # euid = 0
        0x00000613, # li a2,0       # suid = 0
        0x09300893, # li a7,147     # __NR_setresuid
        0x00000073  # ecall
      ].pack('V*'),

      # setresgid(0, 0, 0)
      'PrependSetresgid' => [
        0x00000513, # li a0,0       # rgid = 0
        0x00000593, # li a1,0       # egid = 0
        0x00000613, # li a2,0       # sgid = 0
        0x0aa00893, # li a7,170     # __NR_setresgid
        0x00000073  # ecall
      ].pack('V*'),

      # setregid(0, 0)
      'PrependSetregid' => [
        0x00000513, # li a0,0       # rgid = 0
        0x00000593, # li a1,0       # egid = 0
        0x04700893, # li a7,71      # __NR_setregid
        0x00000073  # ecall
      ].pack('V*'),

      # setgid(0)
      'PrependSetgid' => [
        0x00000513, # li a0,0       # gid = 0
        0x02e00893, # li a7,46      # __NR_setgid
        0x00000073  # ecall
      ].pack('V*')
    }
  end

  def appends_map
    {
      # exit(0)
      'AppendExit' => [
        0x00000513, # li a0,0       # exit code = 0
        0x05d00893, # li a7,93      # __NR_exit
        0x00000073  # ecall
      ].pack('V*')
    }
  end
end
