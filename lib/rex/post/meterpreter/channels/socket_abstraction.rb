# -*- coding: binary -*-

# require 'rex/io/socket_abstraction'
require 'rex/post/meterpreter/channel'

module Rex
module Post
module Meterpreter

###
#
# Abstraction
# ------
#
# This class represents a channel that is streaming.  This means
# that sequential data is flowing in either one or both directions.
#
###
module SocketAbstraction

  module SocketInterface
    include Rex::Socket

    def getsockname
      return super if not channel
      # Find the first host in our chain (our address)
      hops = 0
      csock = channel.client.sock
      while(csock.respond_to?('channel'))
        csock = csock.channel.client.sock
        hops += 1
      end
      _address_family,caddr,_cport = csock.getsockname
      address_family,raddr,_rport = csock.getpeername_as_array
      _maddr,mport = [ channel.params.localhost, channel.params.localport ]
      [ address_family, "#{caddr}#{(hops > 0) ? "-_#{hops}_" : ""}-#{raddr}", mport ]
    end

    def getpeername
      return super if not channel
      maddr,mport = [ channel.params.peerhost, channel.params.peerport ]
      ::Socket.sockaddr_in(mport, maddr)
    end

    %i{localhost localport peerhost peerport}.map do |meth|
      define_method(meth) {
        return super if not channel
        channel.params.send(meth)
      }
    end

    def close
      super
      channel.cleanup_abstraction
      channel.close
    end

    attr_accessor :channel
  end

  #
  # Simple mixin for lsock in order to help avoid a ruby interpreter issue with ::Socket.pair
  # Instead of writing to the lsock, reading from the rsock and then writing to the channel,
  # we use this mixin to directly write to the channel.
  #
  # Note: This does not work with OpenSSL as OpenSSL is implemented natively and requires a real
  # socket to write to and we cant intercept the sockets syswrite at a native level.
  #
  # Note: The deadlock only seems to effect the Ruby build for cygwin.
  #
  module DirectChannelWrite

    def syswrite(buf)
      channel._write(buf)
    end

    attr_accessor :channel
  end

  ##
  #
  # Constructor
  #
  ##

  #
  # Passes the initialization information up to the base class
  #
  def initialize(client, cid, type, flags)
    # sf: initialize_abstraction() before super() as we can get a scenario where dio_write_handler() is called
    # with data to write to the rsock but rsock has not yet been initialized. This happens if the channel
    # is registered (client.add_channel(self) in Channel.initialize) to a session and a 'core_channel_write'
    # request comes in before we have called self.initialize_abstraction()
    initialize_abstraction
    super(client, cid, type, flags)
  end

  ##
  #
  # Remote I/O handlers
  #
  ##

  #
  # Performs a write operation on the right side of the local stream.
  #
  def dio_write_handler(packet, data)
    rv = Rex::ThreadSafe.select(nil, [rsock], nil, 0.01)
    if(rv)
      rsock.syswrite(data)
      return true
    else
      return false
    end
  end

  #
  # Performs a close operation on the right side of the local stream.
  #
  def dio_close_handler(packet)
    rsock.close

    return super(packet)
  end

  #
  # Cleans up the stream abstraction.
  #
  def cleanup
    super

    cleanup_abstraction
  end

  #
  # Wrap the _write() call in order to catch some common, but harmless Windows exceptions
  #
  def _write(*args)
    begin
      super(*args)
    rescue ::Rex::Post::Meterpreter::RequestError => e
      case e.code
      when 10000 .. 10100
        raise ::Rex::ConnectionError.new
      end
    end
  end

end

end; end; end
