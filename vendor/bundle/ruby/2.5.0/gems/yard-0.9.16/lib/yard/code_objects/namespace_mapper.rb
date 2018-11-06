# frozen_string_literal: true
module YARD
  module CodeObjects
    # This module controls registration and accessing of namespace separators
    # for {Registry} lookup.
    #
    # @since 0.9.1
    module NamespaceMapper
      # @!group Registering a Separator for a Namespace

      # Registers a separator with an optional set of valid types that
      # must follow the separator lexically.
      #
      # @param sep [String] the separator string for the namespace
      # @param valid_types [Array<Symbol>] a list of object types that
      #   must follow the separator. If the list is empty, any type can
      #   follow the separator.
      # @example Registering separators for a method object
      #   # Anything after a "#" denotes a method object
      #   register_separator "#", :method
      #   # Anything after a "." denotes a method object
      #   register_separator ".", :method
      def register_separator(sep, *valid_types)
        NamespaceMapper.invalidate

        valid_types.each do |t|
          NamespaceMapper.rev_map[t] ||= []
          NamespaceMapper.rev_map[t] << sep
        end

        NamespaceMapper.map[sep] ||= []
        NamespaceMapper.map[sep] += valid_types
      end

      # Clears the map of separators.
      #
      # @return [void]
      def clear_separators
        NamespaceMapper.invalidate
        NamespaceMapper.map = {}
        NamespaceMapper.rev_map = {}
      end

      # Gets or sets the default separator value to use when no
      # separator for the namespace can be determined.
      #
      # @param value [String, nil] the default separator, or nil to return the
      #   value
      # @example
      #   default_separator "::"
      def default_separator(value = nil)
        if value
          NamespaceMapper.default_separator = Regexp.quote value
        else
          NamespaceMapper.default_separator
        end
      end

      # @!group Separator and Type Lookup Helpers

      # @return [Array<String>] all of the registered separators
      def separators
        NamespaceMapper.map.keys
      end

      # @return [Regexp] the regexp match of all separators
      def separators_match
        NamespaceMapper.map_match
      end

      # @param sep [String] the separator to return types for
      # @return [Array<Symbol>] a list of types registered to a separator
      def types_for_separator(sep)
        NamespaceMapper.map[sep]
      end

      # @param type [String] the type to return separators for
      # @return [Array<Symbol>] a list of separators registered to a type
      def separators_for_type(type)
        NamespaceMapper.rev_map[type]
      end

      # Internal methods to act as a singleton registry
      class << self
        # @!visibility private

        # @return [Hash] a mapping of types to separators
        def map
          @map ||= {}
        end

        # @return [Hash] a reverse mapping of separators to types
        def rev_map
          @rev_map ||= {}
        end

        # Invalidates all separators
        # @return [void]
        def invalidate
          @map_match = nil
        end

        # @return [Regexp] the full list of separators as a regexp match
        def map_match
          @map_match ||= @map.keys.map {|k| Regexp.quote k }.join('|')
        end

        # @return [String] the default separator when no separator can begin
        #   determined.
        attr_accessor :default_separator
      end
    end
  end
end
