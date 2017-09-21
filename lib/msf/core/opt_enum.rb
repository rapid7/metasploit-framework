# -*- coding: binary -*-

module Msf
  ###
  #
  # Enum option.
  #
  ###
  class OptEnum < OptBase
    def type
      return 'enum'
    end

    # This overrides required default from 'false' to 'true'
    def initialize(in_name, attrs = [],
                   required: true, desc: nil, default: nil, enums: [], aliases: [])
      super
    end

    def valid?(value = self.value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return true if value.nil? && !required?

      !value.nil? && enums.include?(value.to_s)
    end

    def normalize(value = self.value)
      if valid?(value)
        value.to_s
      else
        nil
      end
    end

    def desc=(value)
      self.desc_string = value
      desc
    end

    def desc
      str = enums.join(', ') if enums
      "#{desc_string || ''} (Accepted: #{str})"
    end

    protected

    attr_accessor :desc_string # :nodoc:
  end
end
