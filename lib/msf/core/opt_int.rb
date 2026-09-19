# -*- coding: binary -*-

module Msf
  ###
  #
  # Integer option.
  #
  ###
  class OptInt < OptBase
    # @param min [Integer,nil] the smallest value that is considered valid, or
    #   nil for no lower bound.
    # @param max [Integer,nil] the largest value that is considered valid, or
    #   nil for no upper bound.
    def initialize(in_name, attrs = [], min: nil, max: nil, **kwargs)
      @min = min
      @max = max

      super(in_name, attrs, **kwargs)

      if @min && @max && @min > @max
        raise ArgumentError, "#{name}: min (#{@min}) must not be greater than max (#{@max})"
      end

      range = range_description
      self.desc += " #{range}" if range
    end

    # @return [Integer,nil] the smallest value that is considered valid.
    attr_reader :min

    # @return [Integer,nil] the largest value that is considered valid.
    attr_reader :max

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

      if value.present? && (@min || @max)
        int = normalize(value)
        return false if @min && int < @min
        return false if @max && int > @max
      end

      super
    end

    private

    # A human-readable summary of the accepted range, appended to the
    # description so it shows up in `info`, or nil when unbounded.
    def range_description
      if @min && @max
        "(range: #{@min}-#{@max})"
      elsif @min
        "(minimum: #{@min})"
      elsif @max
        "(maximum: #{@max})"
      end
    end
  end
end
