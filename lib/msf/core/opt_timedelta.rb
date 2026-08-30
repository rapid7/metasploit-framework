# frozen_string_literal: true

# -*- coding: binary -*-

module Msf
  class OptTimedelta < OptBase
    TIMEDELTA_REGEX = /\A([+-]?\d+(?:\.\d+)?(?:[smhd])?)+\z/i.freeze

    UNIT_IN_SECONDS = {
      's' => 1,
      'm' => 60,
      'h' => 3_600,
      'd' => 86_400
    }.freeze

    attr_reader :allow_negative

    def initialize(in_name, attrs = [], allow_negative: true, **kwargs)
      super(in_name, attrs, **kwargs)
      @allow_negative = allow_negative
    end

    def type
      'timedelta'
    end

    def normalize(value)
      self.class.parse(value)
    end

    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)

      begin
        parsed_value = self.class.parse(value)
      rescue Msf::OptionValidateError
        return false
      end

      return false if !allow_negative && parsed_value.negative?

      super
    end

    def self.parse(value)
      return 0 if value.nil?
      return value.to_f if value.is_a?(Numeric)

      trimmed_value = value.to_s.strip
      return 0 if trimmed_value.empty?
      return trimmed_value.to_f if trimmed_value.match?(/\A[+-]?\d+(?:\.\d+)?\z/)
      raise Msf::OptionValidateError.new([], message: 'Invalid timedelta format') unless trimmed_value.match?(TIMEDELTA_REGEX)


      total = 0
      trimmed_value.scan(/([+-]?\d+(?:\.\d+)?)([smhd]?)/i) do |amount, unit|
        unit = 's' if unit.blank?
        multiplier = UNIT_IN_SECONDS[unit.downcase]
        total += amount.to_f * multiplier
      end
      total
    end
  end
end