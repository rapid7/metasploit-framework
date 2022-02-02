##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# SingleByte
# ----------
#
# This class implements simple NOP generator for AARCH64
#
###
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name'        => 'Simple',
      'Alias'       => 'armle_simple',
      'Description' => 'Simple NOP generator',
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_AARCH64)
    register_advanced_options(
      [
        OptBool.new('RandomNops', [ false, "Generate a random NOP sled", true ])
      ])
  end

  def generate_sled(length, opts)
    random   = opts['Random']   || datastore['RandomNops']
    nops = [
      0xd503201f,          #  nop
      0xaa0103e1,          #  mov	x1, x1
      0xaa0203e2,          #  mov	x2, x2
      0x2a0303e3,          #  mov	w3, w3
      0x2a0403e4,          #  mov	w4, w4
    ]
    if random
      return ([nops[rand(nops.length)]].pack("V*") * (length/4))
    end
    return ([nops[0]].pack("V*") * (length/4))
  end
end

