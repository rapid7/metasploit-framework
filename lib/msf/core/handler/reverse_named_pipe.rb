# -*- coding: binary -*-
require 'thread'

module Msf
module Handler
###
#
# This module implements the reverse TCP handler.  This means
# that it listens on a port waiting for a connection until
# either one is established or it is told to abort.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseNamedPipe
  include Msf::Handler
  include Msf::Handler::Reverse::Comm

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_tcp'.
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
  # Initializes the reverse TCP handler and ads the options that are required
  # for all reverse TCP payloads, like local host and local port.
  #
  def initialize(info = {})
    super

    register_options([
      OptString.new('PIPENAME', [true, 'Name of the pipe to listen on', 'msf-pipe'])
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

  def pipe_name
    datastore['PIPENAME']
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    queue = ::Queue.new

    local_port = bind_port

    handler_name = "ReverseNamedPipeHandlerListener-#{pipe_name}"
    self.listener_thread = framework.threads.spawn(handler_name, false, queue) { |lqueue|
      loop do
        # Accept a client connection
        begin
          client = listener_sock.accept
          if client
            self.pending_connections += 1
            lqueue.push(client)
          end
        rescue Errno::ENOTCONN
          nil
        rescue StandardError => e
          wlog [
            "#{handler_name}: Exception raised during listener accept: #{e.class}",
            "#{$ERROR_INFO}",
            "#{$ERROR_POSITION.join("\n")}"
          ].join("\n")
        end
      end
    }

    worker_name = "ReverseNamedPipeHandlerWorker-#{pipe_name}"
    self.handler_thread = framework.threads.spawn(worker_name, false, queue) { |cqueue|
      loop do
        begin
          client = cqueue.pop

          unless client
            elog("#{worker_name}: Queue returned an empty result, exiting...")
          end

          # Timeout and datastore options need to be passed through to the client
          opts = {
            datastore:     datastore,
            expiration:    datastore['SessionExpirationTimeout'].to_i,
            comm_timeout:  datastore['SessionCommunicationTimeout'].to_i,
            retry_total:   datastore['SessionRetryTotal'].to_i,
            retry_wait:    datastore['SessionRetryWait'].to_i
          }

          #handle_connection(wrap_aes_socket(client), opts)
        rescue StandardError
          elog("Exception raised from handle_connection: #{$ERROR_INFO.class}: #{$ERROR_INFO}\n\n#{$ERROR_POSITION.join("\n")}")
        end
      end
    }
  end

  def wrap_aes_socket(sock)
    if datastore["PAYLOAD"] !~ %r{java/} || (datastore["AESPassword"] || "") == ""
      return sock
    end

    socks = Rex::Socket.tcp_socket_pair
    socks[0].extend(Rex::Socket::Tcp)
    socks[1].extend(Rex::Socket::Tcp)

    m = OpenSSL::Digest.new('md5')
    m.reset
    key = m.digest(datastore["AESPassword"] || "")

    Rex::ThreadFactory.spawn('Session-AESEncrypt', false) do
      c1 = OpenSSL::Cipher.new('aes-128-cfb8')
      c1.encrypt
      c1.key = key
      sock.put([0].pack('N'))
      sock.put((c1.iv = c1.random_iv))
      buf1 = socks[0].read(4096)
      while buf1 && buf1 != ""
        sock.put(c1.update(buf1))
        buf1 = socks[0].read(4096)
      end
      sock.close
    end

    Rex::ThreadFactory.spawn('Session-AESDecrypt', false) do
      c2 = OpenSSL::Cipher.new('aes-128-cfb8')
      c2.decrypt
      c2.key = key

      iv = ""
      iv << sock.read(16 - iv.length) while iv.length < 16

      c2.iv = iv
      buf2 = sock.read(4096)
      while buf2 && buf2 != ""
        socks[0].put(c2.update(buf2))
        buf2 = sock.read(4096)
      end
      socks[0].close
    end

    socks[1]
  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # Terminate the listener thread
    listener_thread.kill if listener_thread && listener_thread.alive? == true

    # Terminate the handler thread
    handler_thread.kill if handler_thread && handler_thread.alive? == true

    if listener_sock
      begin
        listener_sock.close
      rescue IOError
        # Ignore if it's listening on a dead session
        dlog("IOError closing listener sock; listening on dead session?", LEV_1)
      end
    end
  end

  protected

  attr_accessor :listener_sock # :nodoc:
  attr_accessor :listener_thread # :nodoc:
  attr_accessor :handler_thread # :nodoc:
  attr_accessor :conn_threads # :nodoc:
end
end
end

