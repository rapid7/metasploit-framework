##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  # This may produce incorrect code due to minimal escaping
  Rank = LowRanking

  def initialize
    super(
      'Name'        => 'Bash Brace Expansion Command Encoder',
      'Description' => %q{
        This encoder uses brace expansion in Bash and other shells
        to avoid whitespace without being overly fancy.
      },
      'Author'      => ['wvu', 'egypt'],
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'EncoderType' => Msf::Encoder::Type::CmdUnixBrace
    )
  end

  def encode_block(state, buf)
    # Skip encoding if there are no badchars
    return buf if state.badchars !~ /\s/

    # Perform brace expansion encoding
    "{#{buf.gsub(',', '\\,').gsub(/\s+/, ',')}}"
  end

end
