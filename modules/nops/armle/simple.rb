##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# SingleByte
# ----------
#
# This class implements simple NOP generator for ARM (little endian)
#
###
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name'        => 'Simple',
      'Alias'       => 'armle_simple',
      'Description' => 'Simple NOP generator',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_ARMLE)

    register_advanced_options(
      [
        OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
      ])
  end


  def generate_sled(length, opts)

    badchars = opts['BadChars'] || ''
    random   = opts['Random']   || datastore['RandomNops']

    nops = [
      0xe1a01001,
      0xe1a02002,
      0xe1a03003,
      0xe1a04004,
      0xe1a05005,
      0xe1a06006,
      0xe1a07007,
      0xe1a08008,
      0xe1a09009,
      0xe1a0a00a,
      0xe1a0b00b
    ]

    if random
      return ([nops[rand(nops.length)]].pack("V*") * (length/4))
    end

    return ([nops[0]].pack("V*") * (length/4))
  end
end
