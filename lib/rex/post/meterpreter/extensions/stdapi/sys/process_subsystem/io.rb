#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/post/meterpreter/client'
require 'rex/post/meterpreter/extensions/stdapi/constants'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Sys
module ProcessSubsystem

###
#
# This class provides an input/output interface to an executed
# process' standard input and output.
#
###
class IO

  ##
  #
  # Constructor
  #
  ##

  #
  # Initializes the IO instance.
  #
  def initialize(process)
    self.process = process
  end

  #
  # Writes the supplied buffer to the standard input handle of the
  # executed process.
  #
  def write(buf)
    return process.channel.write(buf)
  end

  #
  # Reads data from the standard output handle of the executed process.
  #
  def read(length = nil)
    return process.channel.read(length)
  end

protected
  attr_accessor :process # :nodoc:

end

end; end; end; end; end; end; end
