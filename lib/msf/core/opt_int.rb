# -*- coding: binary -*-

module Msf
  ###
  #
  # Integer option.
  #
  ###
  class OptInt < OptBase
    # @param minimum [Integer,nil] the smallest value that is considered valid,
    #   or nil for no lower bound.
    # @param maximum [Integer,nil] the largest value that is considered valid,
    #   or nil for no upper bound.
    def initialize(in_name, attrs = [], minimum: nil, maximum: nil, **)
      @minimum = minimum
      @maximum = maximum

      super(in_name, attrs, **)

      if @minimum && @maximum && @minimum > @maximum
        raise ArgumentError, "#{name}: minimum (#{@minimum}) must not be greater than maximum (#{@maximum})"
      end

      range = range_description
      self.desc += " #{range}" if range
    end

    # @return [Integer,nil] the smallest value that is considered valid.
    attr_reader :minimum

    # @return [Integer,nil] the largest value that is considered valid.
    attr_reader :maximum

    def type
      'integer'
    end

    def normalize(value)
      if value.to_s.match(/^0x[a-fA-F\d]+$/)
        value.to_i(16)
      elsif value.present?
        value.to_i
      end
    end

    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)
      return false if value.present? && !value.to_s.match(/^0x[0-9a-fA-F]+$|^-?\d+$/)

      if value.present? && (@minimum || @maximum)
        int = normalize(value)
        return false if @minimum && int < @minimum
        return false if @maximum && int > @maximum
      end

      super
    end

    private

    # A human-readable summary of the accepted range, appended to the
    # description so it shows up in `info`, or nil when unbounded.
    def range_description
      if @minimum && @maximum
        "(range: #{@minimum}-#{@maximum})"
      elsif @minimum
        "(minimum: #{@minimum})"
      elsif @maximum
        "(maximum: #{@maximum})"
      end
    end
  end
end
