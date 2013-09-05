# -*- coding: binary -*-
require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'

module Rex
module Exploitation

###
#
# This class provides an interface to generating cmdstagers.
#
###

class CmdStagerBase

  def initialize(exe)
    @linemax     = 2047 # covers most likely cases
    @exe         = exe
  end

  #
  # Generates the cmd payload including the h2bv2 decoder and encoded payload.
  # The resulting commands also perform cleanup, removing any left over files
  #
  def generate(opts = {})
    # Allow temporary directory override
    @tempdir = opts[:temp]
    @tempdir ||= "%TEMP%\\"
    if (@tempdir == '.')
      @tempdir = ''
    end

    opts[:linemax] ||= @linemax

    generate_cmds(opts)
  end


  #
  # This does the work of actually building an array of commands that
  # when executed will create and run an executable payload.
  #
  def generate_cmds(opts)

    # Initialize an arry of commands to execute
    cmds = []

    # Add the exe building commands
    cmds += generate_cmds_payload(opts)

    # Add the decoder script building commands
    cmds += generate_cmds_decoder(opts)

    compress_commands(cmds, opts)
  end


  #
  # Generate the commands to create an encoded version of the
  # payload file
  #
  def generate_cmds_payload(opts)

    # First encode the payload
    encoded = encode_payload(opts)

    # Now split it up into usable pieces
    parts = slice_up_payload(encoded, opts)

    # Turn each part into a valid command
    parts_to_commands(parts, opts)
  end

  #
  # This method is intended to be override by the child class
  #
  def encode_payload(opts)
    # Defaults to nothing
    ""
  end

  #
  # We take a string of data and turn it into an array of parts.
  #
  # We save opts[:extra] bytes out of every opts[:linemax] for the parts
  # appended and prepended to the resulting elements.
  #
  def slice_up_payload(encoded, opts)
    tmp = encoded.dup

    parts = []
    xtra_len = opts[:extra]
    xtra_len ||= 0
    while (tmp.length > 0)
      parts << tmp.slice!(0, (opts[:linemax] - xtra_len))
    end

    parts
  end

  #
  # Combine the parts of the encoded file with the stuff that goes
  # before / after it -- example "echo " and " >>file"
  #
  def parts_to_commands(parts, opts)
    # Return as-is
    parts
  end



  #
  # Generate the commands that will decode the file we just created
  #
  def generate_cmds_decoder(opts)
    # Defaults to no commands.
    []
  end



  #
  # Compress commands into as few lines as possible. Minimizes the number of
  # commands to execute while maximizing the number of commands per execution.
  #
  def compress_commands(cmds, opts)
    new_cmds = []
    line = ''
    concat = cmd_concat_operator

    # We cannot compress commands if there is no way to combine commands on
    # a single line.
    return cmds if not concat

    cmds.each { |cmd|

      # If this command will fit, concat it and move on.
      if ((line.length + cmd.length + concat.length) < opts[:linemax])
        line << concat if line.length > 0
        line << cmd
        next
      end

      # The command wont fit concat'd to this line, if we have something,
      # we have to add it to the array now.
      if (line.length > 0)
        new_cmds << line
        line = ''
      end

      # If it won't fit even after emptying the current line, error out..
      if (cmd.length > opts[:linemax])
        raise RuntimeError, 'Line too long - %u bytes, max %u' % [cmd.length, opts[:linemax]]
      end

      # It will indeed fit by itself, lets add it.
      line << cmd

    }
    new_cmds << line if (line.length > 0)

    # Return the final array.
    new_cmds
  end

  #
  # Can be overriden.  For exmaple, use for unix use ";" instead
  #
  def cmd_concat_operator
    nil
  end

end
end
end
