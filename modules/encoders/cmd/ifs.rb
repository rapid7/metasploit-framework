##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



class MetasploitModule < Msf::Encoder

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
      'Platform'         => 'unix',
      'EncoderType'      => Msf::Encoder::Type::CmdUnixIfs)
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    # Skip encoding for empty badchars
    if state.badchars.length == 0
      return buf
    end

    # Skip encoding unless space is a badchar
    unless state.badchars.include?(" ")
      return buf
    end

    buf.gsub!(/\s/, '${IFS}')
    return buf
  end

end
