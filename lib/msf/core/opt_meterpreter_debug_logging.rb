# -*- coding: binary -*-

module Msf
  ###
  #
  # Meterpreter Debug Logging option
  #
  ###
  class OptMeterpreterDebugLogging < OptBase
    def initialize(in_name, attrs = [], **kwargs)
      super
    end

    def type
      'meterpreterdebuglogging'
    end

    def validate_on_assignment?
      true
    end

    def valid?(value, check_empty: true)
      return false if !super(value, check_empty: check_empty)

      begin
        _parse_result = self.class.parse_logging_options(value)
        true
      rescue ::ArgumentError
        false
      end
    end

    ##
    #
    # Parses the given Meterpreter Debug Logging string
    #
    ##
    def self.parse_logging_options(value)
      result = {}
      errors = []

      return result if value.nil?

      value = value.strip
      # Match 'rpath:./file', 'rpath:/file', and drive letters e.g. 'rpath:C:/file'
      rpath_regex = %r{^rpath:((\.?/\p{ASCII}+)|(\p{ASCII}:/\p{ASCII}+))}i

      # Check if we log to rpath
      if value.match?(rpath_regex)
        # https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=cmd
        max_length = 260
        rpath_value = value.split('rpath:').last
        if rpath_value.length <= max_length
          result[:rpath] = rpath_value
        else
          errors << "Rpath is too long. Max length: #{max_length}"
        end
      else
        errors << 'Value is not a valid rpath string'
      end

      if errors.any?
        raise ::ArgumentError, "Failed to validate MeterpreterDebugLogging option: #{value} with error/errors: #{errors.join('. ')}"
      end

      result
    end
  end
end
