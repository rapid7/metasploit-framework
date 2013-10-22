##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

  # Has some issues, but overall it's pretty good
  Rank = GoodRanking

  def initialize
    super(
      'Name'             => 'Generic Shell Variable Substitution Command Encoder',
      'Description'      => %q{
        This encoder uses standard Bourne shell variable substitution
      tricks to avoid commonly restricted characters.
      },
      'Author'           => 'hdm',
      'Arch'             => ARCH_CMD)
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)

    # Skip encoding for empty badchars
    if(state.badchars.length == 0)
      return buf
    end

    if (state.badchars.include?("-"))
      # Then neither of the others will work.  Get rid of spaces and hope
      # for the best.  This obviously won't work if the command already
      # has other badchars in it, in which case we're basically screwed.
      if (state.badchars.include?(" "))
        buf.gsub!(/\s/, '${IFS}')
      end
    else
      # Without an escape character we can't escape anything, so echo
      # won't work.  Try perl.
      if (state.badchars.include?("\\"))
        buf = encode_block_perl(state,buf)
      else
        buf = encode_block_bash_echo(state,buf)
      end
    end

    return buf
  end

  #
  # Uses the perl command to hex encode the command string
  #
  def encode_block_perl(state, buf)

    hex = buf.unpack("H*")
    cmd = 'perl -e '
    qot = ',-:.=+!@#$%^&'

    # Find a quoting character to use
    state.badchars.unpack('C*') { |c| qot.delete(c.chr) }

    # Throw an error if we ran out of quotes
    raise RuntimeError if qot.length == 0

    sep = qot[0].chr

    # Convert spaces to IFS...
    if (state.badchars.include?(" "))
      cmd.gsub!(/\s/, '${IFS}')
    end

    # Can we use single quotes to enclose the command string?
    if (state.badchars.include?("'"))

      if (state.badchars.match(/\(|\)/))

        # No paranthesis...
        raise RuntimeError
      end

      cmd << "system\\(pack\\(qq#{sep}H\\*#{sep},qq#{sep}#{hex}#{sep}\\)\\)"

    else
      if (state.badchars.match(/\(|\)/))
        if (state.badchars.include?(" "))
          # No spaces allowed, no paranthesis, give up...
          raise RuntimeError
        end

        cmd << "'system pack qq#{sep}H*#{sep},qq#{sep}#{hex}#{sep}'"
      else
        cmd << "'system(pack(qq#{sep}H*#{sep},qq#{sep}#{hex}#{sep}))'"
      end
    end

    return cmd
  end

  #
  # Uses bash's echo -ne command to hex encode the command string
  #
  def encode_block_bash_echo(state, buf)

    hex = ''

    # Can we use single quotes to enclose the echo arguments?
    if (state.badchars.include?("'"))
      hex = buf.unpack('C*').collect { |c| "\\\\\\x%.2x" % c }.join
    else
      hex = "'" + buf.unpack('C*').collect { |c| "\\x%.2x" % c }.join + "'"
    end

    # Are pipe characters restricted?
    if (state.badchars.include?("|"))
      # How about backticks?
      if (state.badchars.include?("`"))
        # Last ditch effort, dollar paren
        if (state.badchars.include?("$") or state.badchars.include?("("))
          raise RuntimeError
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
    if (state.badchars.include?(" "))
      buf.gsub!(/\s/, '${IFS}')
    end

    return buf
  end

end
