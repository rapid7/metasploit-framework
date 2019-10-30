# -*- coding: binary -*-
require 'rex/socket'
require 'thread'

module Msf
module Handler

###
#
# This module implements the reverse UDP handler.  This means
# that it listens on a port waiting for a connection until
# either one is established or it is told to abort.
#
# This handler depends on having a local host and port to
# listen on.
#
###
module ReverseUdp

  include Msf::Handler

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_udp'.
  #
  def self.handler_type
    return "reverse_udp"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  # A string suitable for displaying to the user
  #
  # @return [String]
  def human_name
    "reverse UDP"
  end

  #
  # Initializes the reverse UDP handler and ads the options that are required
  # for all reverse UDP payloads, like local host and local port.
  #
  def initialize(info = {})
    super

    register_options(
      [
        Opt::LHOST,
        Opt::LPORT(4444)
      ], Msf::Handler::ReverseUdp)

    # XXX: Not supported by all modules
    register_advanced_options(
      [
        OptAddress.new('ReverseListenerBindAddress', [ false, 'The specific IP address to bind to on the local system']),
        OptInt.new('ReverseListenerBindPort', [ false, 'The port to bind to on the local system if different from LPORT' ]),
        OptString.new('ReverseListenerComm', [ false, 'The specific communication channel to use for this listener']),
        OptBool.new('ReverseListenerThreaded', [ true, 'Handle every connection in a new thread (experimental)', false])
      ] +
      Msf::Opt::stager_retry_options,
      Msf::Handler::ReverseUdp)

    self.conn_threads = []
  end

  #
  # Starts the listener but does not actually attempt
  # to accept a connection.  Throws socket exceptions
  # if it fails to start the listener.
  #
  def setup_handler
    ex = false

    comm = case datastore['ReverseListenerComm'].to_s
      when "local"; ::Rex::Socket::Comm::Local
      when /\A[0-9]+\Z/; framework.sessions[datastore['ReverseListenerComm'].to_i]
      else; nil
      end
    unless comm.is_a? ::Rex::Socket::Comm
      comm = nil
    end

    local_port = bind_port
    addrs = bind_address

    addrs.each { |ip|
      begin

        self.listener_sock = Rex::Socket::Udp.create(
          'LocalHost' => ip,
          'LocalPort' => local_port,
          'Comm'      => comm,
          'Context'   =>
            {
              'Msf'        => framework,
              'MsfPayload' => self,
              'MsfExploit' => assoc_exploit
            })

        ex = false

        comm_used = comm || Rex::Socket::SwitchBoard.best_comm( ip )
        comm_used = Rex::Socket::Comm::Local if comm_used == nil

        if( comm_used.respond_to?( :type ) and comm_used.respond_to?( :sid ) )
          via = "via the #{comm_used.type} on session #{comm_used.sid}"
        else
          via = ""
        end

        print_status("Started #{human_name} handler on #{ip}:#{local_port} #{via}")
        break
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{local_port}")
      end
    }
    raise ex if (ex)
  end

  #
  # Closes the listener socket if one was created.
  #
  def cleanup_handler
    stop_handler

    # Kill any remaining handle_connection threads that might
    # be hanging around
    conn_threads.each { |thr|
      thr.kill rescue nil
    }
  end

  #
  # Starts monitoring for an inbound connection.
  #
  def start_handler
    queue = ::Queue.new

    local_port = bind_port

    self.listener_thread = framework.threads.spawn("ReverseUdpHandlerListener-#{local_port}", false, queue) { |lqueue|
      loop do
        # Accept a client connection
        begin
          inbound, peerhost, peerport = self.listener_sock.recvfrom
          next if peerhost.nil?
          cli_opts = {
            'PeerPort' => peerport,
            'PeerHost' => peerhost,
            'LocalPort' => self.listener_sock.localport,
            'Comm' => self.listener_sock.respond_to?(:comm) ? self.listener_sock.comm : nil
          }

          # unless ['::', '0.0.0.0'].any? {|alladdr| self.listener_sock.localhost == alladdr }
          #   cli_opts['LocalHost'] = self.listener_sock.localhost
          # end

          client = Rex::Socket.create_udp(cli_opts)
          client.extend(Rex::IO::Stream)
          if ! client
            wlog("ReverseUdpHandlerListener-#{local_port}: No client received in call to accept, exiting...")
            break
          end

          self.pending_connections += 1
          lqueue.push([client,inbound])
        rescue ::Exception
          wlog("ReverseUdpHandlerListener-#{local_port}: Exception raised during listener accept: #{$!}\n\n#{$@.join("\n")}")
          break
        end
      end
    }

    self.handler_thread = framework.threads.spawn("ReverseUdpHandlerWorker-#{local_port}", false, queue) { |cqueue|
      loop do
        begin
          client, inbound = cqueue.pop

          if ! client
            elog("ReverseUdpHandlerWorker-#{local_port}: Queue returned an empty result, exiting...")
            break
          end

          # Timeout and datastore options need to be passed through to the client
          opts = {
            :datastore    => datastore,
            :expiration   => datastore['SessionExpirationTimeout'].to_i,
            :comm_timeout => datastore['SessionCommunicationTimeout'].to_i,
            :retry_total  => datastore['SessionRetryTotal'].to_i,
            :retry_wait   => datastore['SessionRetryWait'].to_i,
            :udp_session  => inbound
          }

          if datastore['ReverseListenerThreaded']
            self.conn_threads << framework.threads.spawn("ReverseUdpHandlerSession-#{local_port}-#{client.peerhost}", false, client) { |client_copy|
              handle_connection(client_copy, opts)
            }
          else
            handle_connection(client, opts)
          end
        rescue ::Exception
          elog("Exception raised from handle_connection: #{$!.class}: #{$!}\n\n#{$@.join("\n")}")
        end
      end
    }

  end

  #
  # Stops monitoring for an inbound connection.
  #
  def stop_handler
    # Terminate the listener thread
    if (self.listener_thread and self.listener_thread.alive? == true)
      self.listener_thread.kill
      self.listener_thread = nil
    end

    # Terminate the handler thread
    if (self.handler_thread and self.handler_thread.alive? == true)
      self.handler_thread.kill
      self.handler_thread = nil
    end

    if (self.listener_sock)
      self.listener_sock.close
      self.listener_sock = nil
    end
  end

protected

  def bind_port
    port = datastore['ReverseListenerBindPort'].to_i
    port > 0 ? port : datastore['LPORT'].to_i
  end

  def bind_address
    # Switch to IPv6 ANY address if the LHOST is also IPv6
    addr = Rex::Socket.resolv_nbo(datastore['LHOST'])
    # First attempt to bind LHOST. If that fails, the user probably has
    # something else listening on that interface. Try again with ANY_ADDR.
    any = (addr.length == 4) ? "0.0.0.0" : "::0"

    addrs = [ Rex::Socket.addr_ntoa(addr), any  ]

    if not datastore['ReverseListenerBindAddress'].to_s.empty?
      # Only try to bind to this specific interface
      addrs = [ datastore['ReverseListenerBindAddress'] ]

      # Pick the right "any" address if either wildcard is used
      addrs[0] = any if (addrs[0] == "0.0.0.0" or addrs == "::0")
    end

    addrs
  end

  attr_accessor :listener_sock # :nodoc:
  attr_accessor :listener_thread # :nodoc:
  attr_accessor :handler_thread # :nodoc:
  attr_accessor :conn_threads # :nodoc:
end

end
end
