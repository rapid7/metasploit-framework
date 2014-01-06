# -*- coding: binary -*-

require 'rex/post/meterpreter/channels/pool'
require 'rex/post/meterpreter/extensions/stdapi/tlv'

module Rex
module Post
module Meterpreter
module Channels
module Pools

###
#
# StreamPool
# ----------
#
# This class represents a channel that is associated with a
# streaming pool that has no definite end-point.  While this
# may seem a paradox given the stream class of channels, it's
# in fact dinstinct because streams automatically forward
# traffic between the two ends of the channel whereas
# stream pools are always requested data in a single direction.
#
###
class StreamPool < Rex::Post::Meterpreter::Channels::Pool

  include Rex::IO::StreamAbstraction

  ##
  #
  # Constructor
  #
  ##

  # Initializes the file channel instance
  def initialize(client, cid, type, flags)
    super(client, cid, type, flags)

    initialize_abstraction
  end

  ##
  #
  # Streaming pools don't support tell, seek, or eof.
  #
  ##

  #
  # This method returns the current offset into the pool.
  #
  def tell
    raise NotImplementedError
  end

  #
  # This method seeks to an offset in the pool.
  #
  def seek
    raise NotImplementedError
  end

  #
  # This method returns whether or not eof has been returned.
  #
  def eof
    return false
  end

  #
  # Transfers data to the local half of the pool for reading.
  #
  def dio_write_handler(packet, data)
    rv = Rex::ThreadSafe.select(nil, [rsock], nil, 0.01)
    if(rv)
      rsock.write(data)
      return true
    else
      return false
    end
  end

  #
  # Closes the local half of the pool stream.
  #
  def dio_close_handler(packet)
    rsock.close

    return super(packet)
  end

  #
  # Cleans up resources used by the channel.
  #
  def cleanup
    super

    cleanup_abstraction
  end

end

end; end; end; end; end

