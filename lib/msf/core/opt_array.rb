# -*- coding: binary -*-

module Msf
  ###
  #
  # Array option - allows multiple discrete values separated by a delimiter.
  #
  ###
  class OptArray < OptBase
    # Default separator regex - matches comma or whitespace separated values
    DEFAULT_SEPARATOR = /(?:,\s*|\s+)/

    def type
      'array'
    end

    # @param in_name [String] the option name
    # @param attrs [Array] standard option attributes [required, description, default]
    # @param accepted [Array<String>] optional list of accepted values (like OptEnum)
    # @param separator [String, Regexp] the character or regex by which members should be split
    # @param strip_whitespace [Boolean] whether leading/trailing whitespace should be removed from each member
    # @param unique [Boolean] whether duplicate members should be removed
    # @param kwargs additional keyword arguments passed to OptBase
    def initialize(in_name, attrs = [],
                   accepted: nil, separator: nil, strip_whitespace: true, unique: true, **kwargs)
      super(in_name, attrs, **kwargs)
      
      @accepted = accepted ? [*accepted].map(&:to_s) : nil
      @separator = separator || DEFAULT_SEPARATOR
      @strip_whitespace = strip_whitespace
      @unique = unique
    end

    # Validates the array option value
    # @param value [String, Array] the value to validate
    # @param check_empty [Boolean] whether to check for empty required values
    # @param datastore [Hash] the datastore (unused but part of interface)
    # @return [Boolean] true if valid, false otherwise
    def valid?(value = self.value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)
      return true if value.nil? && !required?
      return false if value.nil?

      # Normalize to array
      arr = value_to_array(value)
      
      # If accepted values are defined, validate each member
      if @accepted
        arr.all? do |member|
          if case_sensitive?
            @accepted.include?(member)
          else
            @accepted.map(&:downcase).include?(member.downcase)
          end
        end
      else
        true
      end
    end

    # Normalizes the value to an array with proper formatting
    # @param value [String, Array] the value to normalize
    # @return [Array, nil] normalized array or nil if invalid
    def normalize(value = self.value)
      return nil if value.nil?
      
      arr = value_to_array(value)
      
      # Apply uniqueness if requested
      arr = arr.uniq if @unique
      
      # Normalize case if accepted values are defined and case-insensitive
      if @accepted && !case_sensitive?
        arr = arr.map do |member|
          @accepted.find { |a| a.casecmp?(member) } || member
        end
      end
      
      # Return nil if validation fails
      return nil unless valid?(arr, check_empty: false)
      
      arr
    end

    # Returns a user-friendly display of the value
    # @param value [String, Array] the value to display
    # @return [String] comma-separated string representation
    def display_value(value)
      arr = value.is_a?(Array) ? value : value_to_array(value)
      arr.join(', ')
    rescue
      value.to_s
    end

    # Override desc to include accepted values if defined
    def desc=(value)
      @desc_string = value
      desc
    end

    def desc
      str = @desc_string || ''
      if @accepted
        accepted_str = @accepted.join(', ')
        "#{str} (Accepted: #{accepted_str})"
      else
        str
      end
    end

    # Accessor for accepted values
    attr_reader :accepted

    protected

    # Converts a value to an array
    # @param value [String, Array] the value to convert
    # @return [Array] the resulting array
    def value_to_array(value)
      return value if value.is_a?(Array)
      return [] if value.nil? || value.to_s.empty?
      
      # Split by separator
      arr = value.to_s.split(@separator)
      
      # Strip whitespace from each member if requested
      arr = arr.map(&:strip) if @strip_whitespace
      
      # Remove empty strings
      arr.reject(&:empty?)
    end

    # Determines if accepted values are case-sensitive
    # Uses the same logic as OptEnum - if all accepted values are unique
    # when downcased, then we're case-insensitive
    # @return [Boolean] true if case-sensitive, false otherwise
    def case_sensitive?
      return true unless @accepted
      @accepted.map(&:downcase).uniq.length != @accepted.uniq.length
    end

    attr_accessor :desc_string # :nodoc:
  end
end
