# -*- coding: binary -*-

module Msf
  # Boolean option type
  class OptBool < OptBase
    TRUE_REGEX = /^(y|yes|t|1|true)$/i
    ANY_REGEX = /^(y|yes|n|no|t|f|0|1|true|false)$/i

    # This overrides default from 'nil' to 'false'
    def initialize(in_name, attrs = [],
                   default: false, **kwargs)
      super
    end

    def type
      return 'bool'
    end

    def valid?(value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)
      return true if value.nil? && !required?

      !(value.nil? ||
        value.to_s.empty? ||
        value.to_s.match(ANY_REGEX).nil?)
    end

    def normalize(value)
      !(value.nil? ||
        value.to_s.match(TRUE_REGEX).nil?)
    end
  end
end
