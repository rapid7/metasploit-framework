# -*- coding: binary -*-
require 'thread'
require 'msf/core/post_mixin'

module Msf
module Handler
###
#
# TODO: docs
#
###
module ReverseNamedPipe

  include Msf::Handler

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_named_pipe'.
  #
  def self.handler_type
    "reverse_named_pipe"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  #
  # Initializes the reverse handler and ads the options that are required
  # for reverse named pipe payloads.
  #
  def initialize(info={})
    super

    register_options([
      OptString.new('PIPENAME', [true, 'Name of the pipe to listen on', 'msf-pipe']),
      OptString.new('PIPEHOST', [true, 'Host of the pipe to connect to', '.'])
    ], Msf::Handler::ReverseNamedPipe)
  end

  #
  # Closes the listener socket if one was created.
  #
  def cleanup_handler
    # we're just pretending to be a handler
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    "reverse named pipe"
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    # we're just pretending to be a handler
  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # we're just pretending to be a handler
  end

end
end
end

