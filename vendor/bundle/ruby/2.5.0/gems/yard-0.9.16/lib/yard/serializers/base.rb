# frozen_string_literal: true
module YARD
  module Serializers
    # The abstract base serializer. Serializers allow templates to be
    # rendered to various endpoints. For instance, a {FileSystemSerializer}
    # would allow template contents to be written to the filesystem
    #
    # To implement a custom serializer, override the following methods:
    # * {#serialize}
    # * {#serialized_path}
    #
    # Optionally, a serializer can implement before and after filters:
    # * {#before_serialize}
    # * {#after_serialize}
    #
    # @abstract Override this class to implement a custom serializer.
    class Base
      # All serializer options are saved so they can be passed to other serializers.
      #
      # @return [SymbolHash] the serializer options
      attr_reader :options

      # @group Creating a New Serializer

      # Creates a new serializer with options
      #
      # @param [Hash] opts the options to assign to {#options}
      def initialize(opts = {})
        @options = SymbolHash.new(false).update(opts)
      end

      # @group Serializing an Object

      # Serializes an object.
      #
      # @abstract This method should implement the logic that serializes
      #   +data+ to the respective endpoint. This method should also call
      #   the before and after callbacks {#before_serialize} and {#after_serialize}
      # @param [CodeObjects::Base, String] object the object to serialize the
      #   data for. The object can also be a string (for non-object serialization)
      # @param [String] data the contents that should be serialized
      def serialize(object, data) end

      # The serialized path of an object
      #
      # @abstract This method should return the path of the object on the
      #   endpoint. For instance, for a file serializer, this should return
      #   the filename that represents the object on disk.
      # @param [CodeObjects::Base] object the object to return a path for
      # @return [String] the serialized path of an object
      def serialized_path(object) end

      # Returns whether an object has been serialized
      #
      # @abstract This method should return whether the endpoint already exists.
      #   For instance, a file system serializer would check if the file exists
      #   on disk. You will most likely use +#basepath+ and {#serialized_path} to
      #   get the endpoint's location.
      # @param [CodeObjects::Base] object the object to check existence of
      # @return [Boolean] whether the endpoint exists.
      # @since 0.6.0
      def exists?(object) # rubocop:disable Lint/UnusedMethodArgument
        false
      end

      # @group Callbacks

      # Called before serialization.
      #
      # @abstract Should run code before serialization. Should return false
      #   if serialization should not occur.
      # @return [Boolean] whether or not serialization should occur
      def before_serialize; end

      # Called after serialization.
      #
      # @abstract Should run code after serialization.
      # @param [String] data the data that was serialized.
      # @return [void]
      def after_serialize(data); end
    end
  end
end
