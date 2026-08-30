# -*- coding: binary -*-

module Msf
  ###
  #
  # Session TLV Logging option.
  #
  # Valid values: 'true', 'false', 'console', or 'file:<path>'
  #
  ###
  class OptSessionTlvLogging < OptBase
    VALID_KEYWORDS = %w[true false console].freeze

    def initialize(in_name, attrs = [], **kwargs)
      super
    end

    def type
      'sessiontlvlogging'
    end

    def validate_on_assignment?
      true
    end

    def valid?(value, check_empty: true, datastore: nil)
      return false if !super(value, check_empty: check_empty)
      return true if value.nil? || value.to_s.strip.empty?

      self.class.valid_tlv_logging?(value.to_s.strip)
    end

    def self.valid_tlv_logging?(value)
      return true if VALID_KEYWORDS.any? { |kw| value.casecmp?(kw) }
      return true if value.start_with?('file:') && value.split('file:', 2).last.length > 0

      false
    end
  end
end
