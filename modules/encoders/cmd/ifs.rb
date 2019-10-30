##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  # This may produce incorrect code, such as in quoted strings
  Rank = LowRanking

  def initialize
    super(
      'Name'        => 'Bourne ${IFS} Substitution Command Encoder',
      'Description' => %q{
        This encoder uses Bourne ${IFS} substitution to avoid whitespace
        without being overly fancy.
      },
      'Author'      => ['egypt', 'wvu'],
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'EncoderType' => Msf::Encoder::Type::CmdUnixIFS
    )
  end

  def encode_block(state, buf)
    # Skip encoding if there are no badchars
    return buf if state.badchars !~ /\s/

    # Perform ${IFS} encoding
    buf.gsub(/\s+/, '${IFS}')
  end

end
