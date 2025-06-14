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
                   required: true, **kwargs)
      super
    end

    def valid?(value = self.value, check_empty: true, datastore: nil)
      return false if check_empty && empty_required_value?(value)
      return true if value.nil? && !required?
      return false if value.nil?

      if case_sensitive?
        enums.include?(value.to_s)
      else
        enums.map(&:downcase).include?(value.to_s.downcase)
      end
    end

    def normalize(value = self.value)
      if valid?(value) && !value.nil?
        if case_sensitive?
          value.to_s
        else
          enums.find { |e| e.casecmp? value }
        end
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

    def case_sensitive?
      enums.map(&:downcase).uniq.length != enums.uniq.length
    end

    attr_accessor :desc_string # :nodoc:
  end
end
