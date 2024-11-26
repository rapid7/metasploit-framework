# -*- coding: binary -*-

module Msf
  ###
  #
  # Integer option.
  #
  ###
  class OptInt < OptBase
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

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return false if value.present? && !value.to_s.match(/^0x[0-9a-fA-F]+$|^-?\d+$/)
      super
    end
  end
end
