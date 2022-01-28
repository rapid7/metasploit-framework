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
        debug: 1000,
        info: 2000,
        error: 3000
      }

      attr_accessor :file

      def Logging.open(client, level: :debug, size: 0x2000, file: nil)
        level = Logging::LEVELS[level.to_sym]
        opts = {file: file}
        raise ArgumentError 'Invalid level, must be one of debug, info, or error' if level.nil?
        Channel.create(client, 'core_logging', self, CHANNEL_FLAG_SYNCHRONOUS, [
          {
            'type'  => TLV_TYPE_LOG_LEVEL,
            'value' => level
          },
          {
            'type'  => TLV_TYPE_LOG_SIZE,
            'value' => size
          },
        ], **opts)
      end

      def dio_write_handler(packet, data)
        if @file.nil?
          data.each_line do |line|
            print_line "%yel[Session #{@client.name}]%clr - #{line.strip}"
          end
        else
          ::File.open(@file, 'a') {|fd| fd.write(data) }
        end
      end

      ##
      #
      # Constructor
      #
      ##

      # Initializes the file channel instance
      def initialize(client, cid, type, flags, packet, file: nil)
        @file = file
        super(client, cid, type, flags, packet)
      end

    end
  end
end
