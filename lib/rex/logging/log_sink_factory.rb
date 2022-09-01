# -*- coding: binary -*-


module Rex
  module Logging

    ###
    #
    # LogSinkFactory can instantiate a LogSink based on the given name.
    #
    ###
    module LogSinkFactory
      # Creates a new log sink of the given name. If no name is provided, a default
      # Flatfile log sink is chosen
      #
      # @param [String] name The name of the required log sink within Rex::Logging::Sinks
      # @param [Array] attrs The attributes to use with the given log sink
      # @return [Rex::Logging::LogSink] The newly created log sink
      def self.new(name = nil, *attrs)
        name ||= Rex::Logging::Sinks::Flatfile.name.demodulize
        raise NameError unless available_sinks.include?(name.to_sym)

        log_sink = Rex::Logging::Sinks.const_get(name)
        log_sink.new(*attrs)
      rescue NameError
        raise Rex::ArgumentError, "Could not find logger #{name}, expected one of #{available_sinks.join(', ')}"
      end

      # Returns a list of the available sinks that can be created by this factory
      #
      # @return [Array<Sym>] The available sinks that can be created by this factory
      def self.available_sinks
        Rex::Logging::Sinks.constants - [Rex::Logging::Sinks::Stream.name.demodulize.to_sym]
      end
    end
  end
end
