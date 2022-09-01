##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = NormalRanking

  def initialize
    super(
      'Name'             => 'Perl Command Encoder',
      'Description'      => %q{
        This encoder uses perl to avoid commonly restricted characters.
      },
      'Author'           => 'hdm',
      'Arch'             => ARCH_CMD,
      'Platform'         => 'unix',
      'EncoderType'      => Msf::Encoder::Type::CmdUnixPerl)
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
      buf = encode_block_perl(state,buf)
    end

    return buf
  end

  #
  # Uses the perl command to hex encode the command string
  #
  def encode_block_perl(state, buf)

    hex = buf.unpack("H*").join
    cmd = 'perl -e '
    qot = ',-:.=+!@#$%^&'

    # Convert spaces to IFS...
    if state.badchars.include?(" ")
      if state.badchars.match(/[${IFS}]/n)
        raise EncodingError
      end
      cmd.gsub!(/\s/, '${IFS}')
    end

    # Can we use single quotes to enclose the command string?
    if state.badchars.include?("'")
      if (state.badchars.match(/[()\\]/))
        cmd << perl_e(state, qot, hex)
      else
        # Without quotes, we can use backslash to escape parens so the
        # shell doesn't try to interpreter them.
        cmd << "system\\(pack\\(#{perl_qq(state, qot, hex)}\\)\\)"
      end
    else
      # Quotes are ok, but we still need parens or spaces
      if (state.badchars.match(/[()]/n))
        if state.badchars.include?(" ")
          cmd << perl_e(state, qot, hex)
        else
          cmd << "'system pack #{perl_qq(state, qot, hex)}'"
        end
      else
        cmd << "'system(pack(#{perl_qq(state, qot, hex)}))'"
      end
    end

    return cmd
  end

  def perl_e(state, qot, hex)
    # We don't have parens, quotes, or backslashes so we have to use
    # barewords on the commandline for the argument to the pack
    # function. As a consequence, we can't use things that the shell
    # would interpret, so $ and & become badchars.
    qot.delete("$")
    qot.delete("&")

    # Perl chains -e with newlines, but doesn't automatically add
    # semicolons, so the following will result in the interpreter
    # seeing a file like this:
    #    system
    #    pack
    #    qq^H*^,qq^whatever^
    # Since system and pack require arguments (rather than assuming
    # $_ when no args are given like many other perl functions),
    # this works out to do what we need.
    cmd = "system -e pack -e #{perl_qq(state, qot, hex)}"
    if state.badchars.include?(" ")
      # We already tested above to make sure that these chars are ok
      # if space isn't.
      cmd.gsub!(" ", "${IFS}")
    end

    cmd
  end

  def perl_qq(state, qot, hex)

    # Find a quoting character to use
    state.badchars.unpack('C*') { |c| qot.delete(c.chr) }

    # Throw an error if we ran out of quotes
    raise EncodingError if qot.length == 0

    sep = qot[0].chr
    # Use an explicit length for the H specifier instead of just "H*"
    # in case * is a badchar for the module, and for the case where this
    # ends up unquoted so the shell doesn't try to expand a path.
    "qq#{sep}H#{hex.length}#{sep},qq#{sep}#{hex}#{sep}"
  end
end
