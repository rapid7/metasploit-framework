# -*- coding: binary -*-
require 'rex/socket'

###
#
# This class provides methods for interacting with a UDP socket.
#
###
module Rex::Socket::Udp

  include Rex::Socket

  ##
  #
  # Factory
  #
  ##

  #
  # Creates the client using the supplied hash.
  #
  def self.create(hash = {})
    hash['Proto'] = 'udp'
    # If we have are to bind to a LocalHost we must be a Server to avail of pivoting.
    # Rex::Socket::Parameters will subsequently turn off the sever flag after the correct
    # comm has been chosen.
    if( hash['LocalHost'] )
      hash['Server'] = true
    end
    self.create_param(Rex::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base socket class' creation method that automatically
  # sets the parameter's protocol to UDP.
  #
  def self.create_param(param)
    param.proto = 'udp'
    Rex::Socket.create_param(param)
  end

  ##
  #
  # UDP connected state methods
  #
  ##

  #
  # Write the supplied datagram to the connected UDP socket.
  #
  def write(gram)
    begin
      return syswrite(gram)
    rescue  ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
      return nil
    end
  end

  alias put write

  #
  # Read a datagram from the UDP socket.
  #
  def read(length = 65535)
    if length < 0
      length = 65535
    end
    return sysread(length)
  end

  #
  # Read a datagram from the UDP socket with a timeout
  #
  def timed_read(length = 65535, timeout=def_read_timeout)
    begin
      if ((rv = ::IO.select([ fd ], nil, nil, timeout)) and
          (rv[0]) and (rv[0][0] == fd)
         )
          return read(length)
      else
        return ''
      end
    rescue Exception
      return ''
    end
  end

  #alias send write
  #alias recv read

  ##
  #
  # UDP non-connected state methods
  #
  ##

  #
  # Sends a datagram to the supplied host:port with optional flags.
  #
  def sendto(gram, peerhost, peerport, flags = 0)

    # Catch unconnected IPv6 sockets talking to IPv4 addresses
    peer = Rex::Socket.resolv_nbo(peerhost)
    if (peer.length == 4 and self.ipv == 6)
      peerhost = Rex::Socket.getaddress(peerhost, true)
      if peerhost[0,7].downcase != '::ffff:'
        peerhost = '::ffff:' + peerhost
      end
    end

    begin
      send(gram, flags, Rex::Socket.to_sockaddr(peerhost, peerport))
    rescue  ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
      return nil
    end

  end

  #
  # Receives a datagram and returns the data and host:port of the requestor
  # as [ data, host, port ].
  #
  def recvfrom(length = 65535, timeout=def_read_timeout)

    begin
      if ((rv = ::IO.select([ fd ], nil, nil, timeout)) and
          (rv[0]) and (rv[0][0] == fd)
         )
          data, saddr    = recvfrom_nonblock(length)
          af, host, port = Rex::Socket.from_sockaddr(saddr)

          return [ data, host, port ]
      else
        return [ '', nil, nil ]
      end
    rescue ::Timeout::Error
      return [ '', nil, nil ]
    rescue ::Interrupt
      raise $!
    rescue ::Exception
      return [ '', nil, nil ]
    end
  end

  #
  # Calls recvfrom and only returns the data
  #
  def get(timeout=nil)
    data, saddr, sport = recvfrom(65535, timeout)
    return data
  end

  #
  # The default number of seconds to wait for a read operation to timeout.
  #
  def def_read_timeout
    10
  end

  def type?
    return 'udp'
  end

end

