# frozen_string_literal: true
module YARD
  module Serializers
    # Implements a serializer that reads from and writes to the filesystem.
    class FileSystemSerializer < Base
      # The base path to write data to.
      # @return [String] a base path
      attr_reader :basepath

      def basepath=(value)
        @basepath = options[:basepath] = value
      end

      # The extension of the filename (defaults to +html+)
      #
      # @return [String] the extension of the file. Empty string for no extension.
      attr_reader :extension

      def extension=(value)
        @extension = options[:extension] = value
      end

      # Creates a new FileSystemSerializer with options
      #
      # @option opts [String] :basepath ('doc') the base path to write data to
      # @option opts [String] :extension ('html') the extension of the serialized
      #   path filename. If this is set to the empty string, no extension is used.
      def initialize(opts = {})
        super
        @name_map = nil
        @basepath = (options[:basepath] || 'doc').to_s
        @extension = (options.key?(:extension) ? options[:extension] : 'html').to_s
      end

      # Serializes object with data to its serialized path (prefixed by the +#basepath+).
      #
      # @return [String] the written data (for chaining)
      def serialize(object, data)
        path = File.join(basepath, serialized_path(object))
        log.debug "Serializing to #{path}"
        File.open!(path, "wb") {|f| f.write data }
      end

      # Implements the serialized path of a code object.
      #
      # @param [CodeObjects::Base, CodeObjects::ExtraFileObject, String] object
      #   the object to get a path for. The path of a string is the string itself.
      # @return [String] if object is a String, returns
      #   object, otherwise the path on disk (without the basepath).
      def serialized_path(object)
        return object if object.is_a?(String)

        if object.is_a?(CodeObjects::ExtraFileObject)
          fspath = ['file.' + object.name + (extension.empty? ? '' : ".#{extension}")]
        else
          objname = object != YARD::Registry.root ? mapped_name(object) : "top-level-namespace"
          objname += '_' + object.scope.to_s[0, 1] if object.is_a?(CodeObjects::MethodObject)
          fspath = [objname + (extension.empty? ? '' : ".#{extension}")]
          if object.namespace && object.namespace.path != ""
            fspath.unshift(*object.namespace.path.split(CodeObjects::NSEP))
          end
        end

        File.join(encode_path_components(*fspath))
      end

      # Checks the disk for an object and returns whether it was serialized.
      #
      # @param [CodeObjects::Base] object the object to check
      # @return [Boolean] whether an object has been serialized to disk
      def exists?(object)
        File.exist?(File.join(basepath, serialized_path(object)))
      end

      private

      # Builds a filename mapping from object paths to filesystem path names.
      # Needed to handle case sensitive YARD objects mapped into a case
      # insensitive filesystem. Uses with {#mapped_name} to determine the
      # mapping name for a given object.
      #
      # @note In order to use filesystem name mapping, you must initialize
      #   the serializer object after preparing the {YARD::Registry}.
      def build_filename_map
        @name_map = {}
        YARD::Registry.all.each do |object|
          lpath = nil
          if object.parent && object.parent.type != :root
            lpath = object.parent.path + "::" + object.name.to_s.downcase
          else
            lpath = object.path.downcase
          end

          @name_map[lpath] ||= {}
          size = @name_map[lpath].size
          name = "#{object.name}#{size > 0 ? "_" * size : ""}"
          @name_map[lpath][object.name] = name
        end
      end

      # @return [String] the filesystem mapped name of a given object.
      def mapped_name(object)
        build_filename_map unless @name_map
        map = @name_map[object.path.downcase]
        map && map[object.name] ? map[object.name] : object.name.to_s
      end

      # Remove special chars from filenames.
      # Windows disallows \ / : * ? " < > | but we will just remove any
      # non alphanumeric (plus period, underscore and dash).
      def encode_path_components(*components)
        components.map! do |p|
          p.gsub(/[^\w\.-]/) do |x|
            encoded = String.new('_')

            x.each_byte {|b| encoded << ("%X" % b) }
            encoded
          end
        end
      end
    end
  end
end
