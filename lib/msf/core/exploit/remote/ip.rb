# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for communicating with a host over raw IP
#
###
module Exploit::Remote::Ip

  #
  # Initializes an instance of an exploit module that sends
  # raw IP datagrams.
  #
  def initialize(info = {})
    super

    register_options(
      [
        Opt::RHOST,
      ], Msf::Exploit::Remote::Ip)
  end

  #
  # Creates an IP socket for communicating with a remote host
  #
  def connect_ip(global = true, opts={})

    begin
      nsock = Rex::Socket::Ip.create(
        'Context'   =>
          {
            'Msf'        => framework,
            'MsfExploit' => self,
          })

      # Set this socket to the global socket as necessary
      self.ip_sock = nsock if (global)

      # Add this socket to the list of sockets created by this exploit
      add_socket(nsock)

      return nsock
    rescue ::Exception => e
      print_line(" ")
      print_error(
        "This module is configured to use a raw IP socket. " +
        "On Unix systems, only the root user is allowed to create raw sockets. " +
        "Please run the framework as root to use this module."
      )
      print_line(" ")
      nil
    end
  end

  #
  # Closes the IP socket
  #
  def disconnect_ip(nsock = self.ip_sock)
    begin
      if (nsock)
        nsock.close
      end
    rescue IOError
    end

    if (nsock == ip_sock)
      self.ip_sock = nil
    end

    # Remove this socket from the list of sockets created by this exploit
    remove_socket(nsock)
  end

  #
  # Claims the IP socket if the payload so desires.
  # No exploits use raw socket payloads yet...
  #
  def handler(nsock = self.ip_sock)
    true
  end

  #
  # Performs cleanup, closes the socket if necessary
  #
  def cleanup
    super
    disconnect_ip
  end

  #
  # Sends a datagram to the host specified in RHOST
  #
  def ip_write(dgram)
    return nil if not ip_sock
    ip_sock.sendto(dgram, rhost)
  end

  ##
  #
  # Wrappers for getters
  #
  ##

  #
  # Returns the target host
  #
  def rhost
    datastore['RHOST']
  end


protected

  attr_accessor :ip_sock

end
end
