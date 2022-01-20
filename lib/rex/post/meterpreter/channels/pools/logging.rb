# -*- coding: binary -*-

require 'rex/post/meterpreter/channels/pools/stream_pool'

module Rex::Post::Meterpreter
  module Channels::Pools

    ###
    #
    # Logging
    # -------
    #
    # This class represents a channel that is associated with a logging stream
    # on the remote half of the meterpreter connection.
    #
    ###
    class Logging < Rex::Post::Meterpreter::Channels::Pools::StreamPool

      ##
      #
      # Factory
      #
      ##

      LEVELS = {
        info: 1000,
        debug: 2000,
        error: 3000
      }

      def Logging.open(client, level: :debug, size: 0x2000)
        level = Logging::LEVELS[level.to_sym]
        raise ArgumentError 'Invalid level, must be one of debug, info, or error' if level.nil?
        channel =  Channel.create(client, 'core_logging', self, CHANNEL_FLAG_SYNCHRONOUS, [
          {
            'type'  => TLV_TYPE_LOG_LEVEL,
            'value' => level
          },
          {
            'type'  => TLV_TYPE_LOG_SIZE,
            'value' => size
          },
        ])

      end

      ##
      #
      # Constructor
      #
      ##

      # Initializes the file channel instance
      def initialize(client, cid, type, flags, packet)
        super(client, cid, type, flags, packet)
      end

    end
  end
end
