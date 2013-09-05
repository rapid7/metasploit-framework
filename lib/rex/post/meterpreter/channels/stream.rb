#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/io/stream_abstraction'
require 'rex/post/meterpreter/channel'

module Rex
module Post
module Meterpreter

###
#
# Stream
# ------
#
# This class represents a channel that is streaming.  This means
# that sequential data is flowing in either one or both directions.
#
###
class Stream < Rex::Post::Meterpreter::Channel

  include Rex::IO::StreamAbstraction

  class << self
    def cls
      return CHANNEL_CLASS_STREAM
    end
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
      rsock.write(data)
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

end

end; end; end

