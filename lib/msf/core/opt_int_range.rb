# -*- coding: binary -*-

module Msf
  ###
  #
  # Integer range option. A maximum value can be specified. Negative numbers are
  # not supported due to - being used for ranges. Numbers can be excluded by
  # using the ! prefix.
  #
  ###
  class OptIntRange < OptBase
    attr_reader :maximum

    def initialize(in_name, attrs = [],
                   required: true, **kwargs)
      super
      @maximum = kwargs.fetch(:maximum, nil)
    end

    def type
      'integer range'
    end

    def normalize(value)
      value.to_s.gsub(/\s/, '')
    end

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)

      if value.present?
        value = value.to_s.gsub(/\s/, '')
        return false unless value =~ /\A(!?\d+|!?\d+-\d+)(,(!?\d+|!?\d+-\d+))*\Z/
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
            break if @maximum && num > @maximum
            next if exclude.any? { |exclude_range| exclude_range.cover?(num) }

            yielder << num
          end
        end
      end
    end
  end
end
