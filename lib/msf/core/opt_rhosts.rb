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

    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)
      return false unless value.is_a?(String) || value.is_a?(NilClass)

      if !value.nil? && !value.empty?
        rhost_walker = datastore ? Msf::RhostsWalker.new(value, datastore) : Msf::RhostsWalker.new(value)
        return rhost_walker.valid?
      end

      super
    end
  end
end
