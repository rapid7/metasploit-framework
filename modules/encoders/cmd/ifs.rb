##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

  # Below normal ranking because this will produce incorrect code a lot of
  # the time.
  Rank = LowRanking

  def initialize
    super(
      'Name'             => 'Generic ${IFS} Substitution Command Encoder',
      'Description'      => %q{
        This encoder uses standard Bourne shell variable substitution
        to avoid spaces without being overly fancy.
      },
      'Author'           => 'egypt',
      'Arch'             => ARCH_CMD,
      'Platform'         => 'unix')
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    buf.gsub!(/\s/, '${IFS}')
    return buf
  end

end
