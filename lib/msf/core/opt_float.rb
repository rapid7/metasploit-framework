# -*- coding: binary -*-

module Msf
  ###
  #
  # Float option.
  #
  ###
  class OptFloat < OptBase
    def type
      'float'
    end

    def normalize(value)
      Float(value) if value.present? && valid?(value)
    end

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      Float(value) rescue return false if value.present?
      super
    end
  end
end
