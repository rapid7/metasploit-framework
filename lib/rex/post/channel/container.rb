# -*- coding: binary -*-

module Rex
  module Post
    module Channel
      ###
      #
      # This interface is meant to be included by things that are meant to contain
      # zero or more channel instances in the form of a hash.
      #
      ###
      module Container
        #
        # Initializes the channel association hash
        #
        def initialize_channels
          self.channels = {}
        end

        #
        # Adds a channel to the container that is indexed by its channel identifier
        #
        def add_channel(channel)
          channels[channel.cid] = channel
        end

        #
        # Looks up a channel instance based on its channel identifier
        #
        def find_channel(cid)
          return channels[cid]
        end

        #
        # Removes a channel based on its channel identifier
        #
        def remove_channel(cid)
          return channels.delete(cid)
        end

        #
        # The hash of channels.
        #
        attr_reader :channels

        protected

        attr_writer :channels # :nodoc:
      end
    end
  end
end
