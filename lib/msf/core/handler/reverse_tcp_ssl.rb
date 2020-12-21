# -*- coding: binary -*-
require 'rex/socket'
require 'thread'
require 'msf/core/handler/reverse_tcp'

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
module ReverseTcpSsl

  include Msf::Handler::ReverseTcp
  include Msf::Handler::Reverse::SSL

  #
  # Returns the string representation of the handler type, in this case
  # 'reverse_tcp_ssl'.
  #
  def self.handler_type
    return "reverse_tcp_ssl"
  end

  #
  # Returns the connection-described general handler type, in this case
  # 'reverse'.
  #
  def self.general_handler_type
    "reverse"
  end

  #
  # Starts the listener but does not actually attempt
  # to accept a connection.  Throws socket exceptions
  # if it fails to start the listener.
  #
  def setup_handler
    if !datastore['Proxies'].blank? && !datastore['ReverseAllowProxy']
      raise RuntimeError, "TCP connect-back payloads cannot be used with Proxies. Use 'set ReverseAllowProxy true' to override this behaviour."
    end

    ex = false

    comm = select_comm
    local_port = bind_port
    bind_addresses.each { |ip|
      begin

        self.listener_sock = Rex::Socket::SslTcpServer.create(
          'LocalHost' => ip,
          'LocalPort' => local_port,
          'Comm'      => comm,
          'SSLCert'   => datastore['HandlerSSLCert'],
          'Context'   =>
            {
              'Msf'        => framework,
              'MsfPayload' => self,
              'MsfExploit' => assoc_exploit
            })

        ex = false

        via = via_string_for_ip(ip, comm)
        print_status("Started reverse SSL handler on #{ip}:#{local_port} #{via}")
        break
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{local_port}")
      end
    }
    raise ex if (ex)
  end

end

end
end
