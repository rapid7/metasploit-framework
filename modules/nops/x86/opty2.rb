##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/nop/opty2'


###
#
# Opty2
# -----
#
# This class implements single-byte NOP generation for X86.  It takes from
# ADMmutate and from spoonfu.
#
###
class MetasploitModule < Msf::Nop

  def initialize
    super(
      'Name'        => 'Opty2',
      'Description' => 'Opty2 multi-byte NOP generator',
      'Author'      => [ 'spoonm', 'optyx' ],
      'License'     => MSF_LICENSE,
      'Arch'        => ARCH_X86)
  end

  def generate_sled(length, opts = {})
    opty = Rex::Nop::Opty2.new(
      opts['BadChars'] || '',
      opts['SaveRegisters'])

    opty.generate_sled(length)
  end
end
