# frozen_string_literal: true
module YARD
  module I18n
    # Acts as a container for {Message} objects.
    #
    # @since 0.8.1
    class Messages
      include Enumerable

      # Creates a new container.
      def initialize
        @messages = {}
      end

      # Enumerates each {Message} in the container.
      #
      # @yieldparam [Message] message the next message object in
      #   the enumeration.
      # @return [void]
      def each(&block)
        @messages.each_value(&block)
      end

      # @param [String] id the message ID to perform a lookup on.
      # @return [Message, nil] a registered message for the given +id+,
      #   or nil if no message for the ID is found.
      def [](id)
        @messages[id]
      end

      # Registers a {Message}, the mssage ID of which is +id+. If
      # corresponding +Message+ is already registered, the previously
      # registered object is returned.
      #
      # @param [String] id the ID of the message to be registered.
      # @return [Message] the registered +Message+.
      def register(id)
        @messages[id] ||= Message.new(id)
      end

      # Checks if this messages list is equal to another messages list.
      #
      # @param [Messages] other the container to compare.
      # @return [Boolean] whether +self+ and +other+ is equivalence or not.
      def ==(other)
        other.is_a?(self.class) &&
          @messages == other.messages
      end

      protected

      # @return [Hash{String=>Message}] the set of message objects
      attr_reader :messages
    end
  end
end
