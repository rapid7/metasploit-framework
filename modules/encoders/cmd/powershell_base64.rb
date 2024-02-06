##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
include Msf::Post::Windows
class MetasploitModule < Msf::Encoder
  Rank = ExcellentRanking

  def initialize
    super(
      'Name'             => 'Powershell Base64 Command Encoder',
      'Description'      => %q{
        This encodes the command as a base64 encoded command for powershell.
      },
      'Author'           => 'Ben Campbell',
      'Arch'             => ARCH_CMD,
      'Platform'         => 'win')
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)

    # Skip encoding for empty badchars
    if state.badchars.length == 0
      return buf
    end

    if (state.badchars.include? '-') || (state.badchars.include? ' ')
      return buf
    end

    cmd = encode_buf(buf)

    if state.badchars.include? '='
        while cmd.include? '='
          buf << " "
          cmd = encode_buf(buf)
        end
    end

    cmd
  end

  def encode_buf(buf)
    # From https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules?view=powershell-7.3
    # To include a single quotation mark in a single-quoted string, use a second consecutive single quote. For example:
    # 'don''t' would be the string "don't" but using single quotes.
    #
    # Note that we can't use double quotes here as double quote strings in PowerShell are classed as expandable strings
    # and we don't want expansion here, as this might cause any potential elements starting with $ to be interpreted
    # as a variable within the string to be replaced by that variable's value.
    #
    # The use of quotes also ensures that we get around the issue with cmd.exe understanding & as a symbol for
    # "also execute this command", whereas in PowerShell it is a reserved character, so not quoting the string
    # will result in the & being interpreted by PowerShell and the command failing on an interpretation error in PowerShell itself.
    base64 = Rex::Text.encode_base64(Rex::Text.to_unicode("cmd.exe /c 'start #{Msf::Post::Windows.escape_powershell_literal(buf)} '"))
    cmd = "powershell -w hidden -nop -e #{base64}"
  end
end
