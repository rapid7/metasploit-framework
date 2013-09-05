#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/io'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Fs

##
#
# The IO class acts as a base class for things that would normally implement
# the IO interface.  The methods it implements are for general operations that
# are common to all channels, such as read, write, and close.
#
##
class IO < Rex::Post::IO

  #
  # Read the specified number of bytes from the channel.
  #
  def sysread(length = nil)
    self.filed.read(length)
  end

  alias read sysread

  #
  # Writes the supplied buffer to the channel.
  #
  def syswrite(buf)
    self.filed.write(buf)
  end

  alias write syswrite

  #
  # Closes the channel.
  #
  def close
    self.filed.close
  end

end

end; end; end; end; end; end
