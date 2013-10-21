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
  # Initializes the reverse TCP SSL handler and adds the certificate option.
  #
  def initialize(info = {})
    super
    register_advanced_options(
      [
        OptPath.new('SSLCert',    [ false, 'Path to a custom SSL certificate (default is randomly generated)'])
      ], Msf::Handler::ReverseTcpSsl)

  end

  #
  # Starts the listener but does not actually attempt
  # to accept a connection.  Throws socket exceptions
  # if it fails to start the listener.
  #
  def setup_handler
    if datastore['Proxies']
      raise RuntimeError, 'TCP connect-back payloads cannot be used with Proxies'
    end

    ex = false
    # Switch to IPv6 ANY address if the LHOST is also IPv6
    addr = Rex::Socket.resolv_nbo(datastore['LHOST'])
    # First attempt to bind LHOST. If that fails, the user probably has
    # something else listening on that interface. Try again with ANY_ADDR.
    any = (addr.length == 4) ? "0.0.0.0" : "::0"

    addrs = [ Rex::Socket.addr_ntoa(addr), any  ]

    comm  = datastore['ReverseListenerComm']
    if comm.to_s == "local"
      comm = ::Rex::Socket::Comm::Local
    else
      comm = nil
    end

    if not datastore['ReverseListenerBindAddress'].to_s.empty?
      # Only try to bind to this specific interface
      addrs = [ datastore['ReverseListenerBindAddress'] ]

      # Pick the right "any" address if either wildcard is used
      addrs[0] = any if (addrs[0] == "0.0.0.0" or addrs == "::0")
    end
    addrs.each { |ip|
      begin

        comm.extend(Rex::Socket::SslTcp)
        self.listener_sock = Rex::Socket::SslTcpServer.create(
        'LocalHost' => datastore['LHOST'],
        'LocalPort' => datastore['LPORT'].to_i,
        'Comm'      => comm,
        'SSLCert'	=> datastore['SSLCert'],
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

        print_status("Started reverse SSL handler on #{ip}:#{datastore['LPORT']} #{via}")
        break
      rescue
        ex = $!
        print_error("Handler failed to bind to #{ip}:#{datastore['LPORT']}")
      end
    }
    raise ex if (ex)
  end

end

end
end
