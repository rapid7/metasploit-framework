# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for communicating with a host over UDP
#
###
module Exploit::Remote::Udp

  #
  # Initializes an instance of an exploit module that exploits a
  # vulnerability in a UDP service
  #
  def initialize(info = {})
    super

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT,
      ], Msf::Exploit::Remote::Udp)

    register_advanced_options(
      [
        Opt::CPORT,
        Opt::CHOST
      ], Msf::Exploit::Remote::Udp
    )
  end

  def deregister_udp_options
    deregister_options('RHOST', 'RPORT')
  end

  #
  # Creates a UDP socket for communicating with a remote host
  #
  def connect_udp(global = true, opts={})
    nsock = Rex::Socket::Udp.create(
      'PeerHost'  =>  opts['RHOST'] || rhost,
      'PeerPort'  => (opts['RPORT'] || rport).to_i,
      'LocalHost' =>  opts['CHOST'] || chost || "0.0.0.0",
      'LocalPort' => (opts['CPORT'] || cport || 0).to_i,
      'Context'   =>
        {
          'Msf'        => framework,
          'MsfExploit' => self,
        })

    # Set this socket to the global socket as necessary
    self.udp_sock = nsock if (global)

    # Add this socket to the list of sockets created by this exploit
    add_socket(nsock)

    return nsock
  end

  #
  # Closes the UDP socket
  #
  def disconnect_udp(nsock = self.udp_sock)
    begin
      if (nsock)
        nsock.shutdown
        nsock.close
      end
    rescue IOError
    end

    if (nsock == udp_sock)
      self.udp_sock = nil
    end

    # Remove this socket from the list of sockets created by this exploit
    remove_socket(nsock)
  end

  #
  # Claims the UDP socket if the payload so desires.
  #
  def handler(nsock = self.udp_sock)
    # If the handler claims the socket, then we don't want it to get closed
    # during cleanup
    if ((rv = super) == Handler::Claimed)
      if (nsock == self.udp_sock)
        self.sock = nil
      end

      # Remove this socket from the list of sockets so that it will not be
      # aborted.
      remove_socket(nsock)
    end

    return rv
  end

  #
  # Performs cleanup, disconnects the socket if necessary
  #
  def cleanup
    super
    disconnect_udp
  end

  ##
  #
  # Wrappers for getters
  #
  ##

  #
  # Returns the local host for outgoing connections
  #
  def chost
    datastore['CHOST']
  end

  #
  # Returns the local port for outgoing connections
  #
  def cport
    datastore['CPORT']
  end

  #
  # Returns the local host
  #
  def lhost
    datastore['LHOST']
  end

  #
  # Returns the local port
  #
  def lport
    datastore['LPORT']
  end

  #
  # Returns the target host
  #
  def rhost
    datastore['RHOST']
  end

  #
  # Returns the remote port
  #
  def rport
    datastore['RPORT']
  end

protected

  attr_accessor :udp_sock

end
end

