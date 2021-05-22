# -*- coding: binary -*-

module Msf
  ###
  #
  # RHosts option
  #
  ###
  class OptRhosts < OptBase
    def type
      'rhosts'
    end

    def validate_on_assignment?
      false
    end

    def normalize(value)
      value
    end

    def valid?(value, check_empty: true)
      return false if check_empty && empty_required_value?(value)
      return false unless value.is_a?(String) || value.is_a?(NilClass)

      if !value.nil? && value.empty? == false
        return Msf::RhostsWalker.new(value).valid?
      end

      super
    end
  end
end
