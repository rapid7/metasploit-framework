# -*- coding: binary -*-
require 'rex/socket'
require 'thread'

module Msf
module Handler
###
#
# This module implements the reverse SCTP handler.  This means
# that it listens on a port waiting for a connection until
# either one is established or it is told to abort.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseSctp
  include Msf::Handler
  include Msf::Handler::Reverse
  include Msf::Handler::Reverse::Comm

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_sctp'.
  #
  def self.handler_type
    "reverse_sctp"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  #
  # Initializes the reverse SCTP handler and ads the options that are required
  # for all reverse SCTP payloads, like local host and local port.
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
      Msf::Handler::ReverseSctp
    )

    self.conn_threads = []
  end

  def setup_handler
    if !datastore['Proxies'].blank? && !datastore['ReverseAllowProxy']
      raise RuntimeError, "SCTP connect-back payloads cannot be used with Proxies. Use 'set ReverseAllowProxy true' to override this behaviour."
    end

    ex = false

    comm = select_comm
    local_port = bind_port

    bind_addresses.each do |ip|
      begin
        self.listener_sock = Rex::Socket::SctpServer.create(
          'LocalHost' => ip,
          'LocalPort' => local_port,
          'Comm'      => comm,
          'Context'   =>
          {
            'Msf'        => framework,
            'MsfPayload' => self,
            'MsfExploit' => assoc_exploit
          })
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{local_port}:- #{comm} -")
      else
        ex = false
        via = via_string(self.listener_sock.client) if self.listener_sock.respond_to?(:client)
        print_status("Started #{human_name} handler on #{ip}:#{local_port} #{via}")
        break
      end
    end
    raise ex if (ex)
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
    "reverse SCTP"
  end

  # A URI describing what the payload is configured to use for transport
  def payload_uri
    addr = datastore['LHOST']
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "sctp://#{uri_host}:#{datastore['LPORT']}"
  end

  def comm_string
    if listener_sock.nil?
      "(setting up)"
    else
      via_string(listener_sock.client) if listener_sock.respond_to?(:client)
    end
  end

  # A URI describing where we are listening
  #
  # @param addr [String] the address that
  # @return [String] A URI of the form +scheme://host:port/+
  def listener_uri(addr = datastore['ReverseListenerBindAddress'])
    addr = datastore['LHOST'] if addr.nil? || addr.empty?
    uri_host = Rex::Socket.is_ipv6?(addr) ? "[#{addr}]" : addr
    "sctp://#{uri_host}:#{bind_port}"
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    queue = ::Queue.new

    local_port = bind_port

    handler_name = "ReverseSctpHandlerListener-#{local_port}"
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

    worker_name = "ReverseSctpHandlerWorker-#{local_port}"
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
              handle_connection(client_copy, opts)
            end
          else
            handle_connection(client, opts)
          end
        rescue StandardError => e
          elog('Exception raised from handle_connection', error: e)
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
