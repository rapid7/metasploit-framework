##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

  def initialize
    super(
      'Name'             => 'The "none" Encoder',
      'Description'      => %q{
        This "encoder" does not transform the payload in any way.
      },
      'Author'           => 'spoonm',
      'License'          => MSF_LICENSE,
      'Arch'             => ARCH_ALL,
      'EncoderType'      => Msf::Encoder::Type::Raw)
  end

  #
  # Simply return the buf straight back.
  #
  def encode_block(state, buf)
    buf
  end

end
