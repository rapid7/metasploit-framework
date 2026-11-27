# -*- coding: binary -*-

module Msf
  ###
  #
  # Integer range option. An optional maximum value can be specified, and values
  # that reference an included number above it are rejected. Negative numbers are
  # not supported due to - being used for ranges. Numbers can be excluded by
  # using the ! prefix.
  #
  ###
  class OptIntRange < OptBase
    # @return [Integer, nil] the largest value an included number may take, or
    #   nil when the range is unbounded.
    attr_reader :maximum

    def initialize(in_name, attrs = [],
                   required: true, maximum: nil, **)
      super(in_name, attrs, required: required, **)
      @maximum = maximum
    end

    def type
      'integer range'
    end

    def normalize(value)
      value.to_s.gsub(/\s/, '')
    end

    # @param value [String] the range specification to validate.
    # @return [Boolean] true when the value is a well-formed range whose
    #   included numbers all fall within {#maximum} (when one is set).
    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)

      if value.present?
        value = value.to_s.gsub(/\s/, '')
        return false unless value =~ /\A(!?\d+|!?\d+-\d+)(,(!?\d+|!?\d+-\d+))*\Z/
        return false if maximum && self.class.parse(value).any? { |num| num > maximum }
      end

      super
    end

    def self.parse(value)
      include = []
      exclude = []

      value.split(',').each do |range_str|
        destination = range_str.start_with?('!') ? exclude : include

        range_str.delete_prefix!('!')
        if range_str.include?('-')
          start_range, end_range = range_str.split('-').map(&:to_i)
          range = (start_range..end_range)
        else
          single_value = range_str.to_i
          range = (single_value..single_value)
        end

        destination << range
      end

      Enumerator.new do |yielder|
        include.each do |include_range|
          include_range.each do |num|
            next if exclude.any? { |exclude_range| exclude_range.cover?(num) }

            yielder << num
          end
        end
      end
    end
  end
end
