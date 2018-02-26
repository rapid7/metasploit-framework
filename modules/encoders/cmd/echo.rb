##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = GoodRanking

  def initialize
    super(
      'Name'             => 'Echo Command Encoder',
      'Description'      => %q{
        This encoder uses echo and backlash escapes to avoid commonly restricted characters.
      },
      'Author'           => 'hdm',
      'Arch'             => ARCH_CMD,
      'Platform'         => 'unix',
      'EncoderType'      => Msf::Encoder::Type::CmdUnixEcho)
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    # Skip encoding for empty badchars
    if state.badchars.length == 0
      return buf
    end

    if state.badchars.include?("-")
      raise EncodingError
    else
      # Without an escape character we can't escape anything, so echo
      # won't work.
      if state.badchars.include?("\\")
        raise EncodingError
      else
        buf = encode_block_bash_echo(state,buf)
      end
    end

    return buf
  end

  #
  # Uses bash's echo -ne command to hex encode the command string
  #
  def encode_block_bash_echo(state, buf)

    hex = ''

    # Can we use single quotes to enclose the echo arguments?
    if state.badchars.include?("'")
      hex = buf.unpack('C*').collect { |c| "\\\\\\x%.2x" % c }.join
    else
      hex = "'" + buf.unpack('C*').collect { |c| "\\x%.2x" % c }.join + "'"
    end

    # Are pipe characters restricted?
    if state.badchars.include?("|")
      # How about backticks?
      if state.badchars.include?("`")
        # Last ditch effort, dollar paren
        if state.badchars.include?("$") or state.badchars.include?("(")
          raise EncodingError
        else
          buf = "$(/bin/echo -ne #{hex})"
        end
      else
        buf = "`/bin/echo -ne #{hex}`"
      end
    else
      buf = "/bin/echo -ne #{hex}|sh"
    end

    # Remove spaces from the command string
    if state.badchars.include?(" ")
      buf.gsub!(/\s/, '${IFS}')
    end

    return buf
  end
end
