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
  class Audio < Rex::Post::Meterpreter::Channels::Pool

    include Rex::IO::StreamAbstraction

    ##
    #
    # Factory
    #
    ##

    #
    # This method returns an instance of a file pool channel that can be read
    # from, written to, seeked on, and other interacted with.
    #
    def Audio.open(client)
      return Channel.create(client, 'stdapi_net_mic_broadcast',
                            self, CHANNEL_FLAG_SYNCHRONOUS)
    end

    ##
    #
    # Constructor
    #
    ##

    # Initializes the file channel instance
    def initialize(client, cid, type, flags)
      super(client, cid, type, flags)
    end

  end

end; end; end; end; end

