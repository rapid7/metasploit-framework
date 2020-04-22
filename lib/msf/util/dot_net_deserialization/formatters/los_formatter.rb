module Msf
module Util
module DotNetDeserialization
module Formatters
module LosFormatter

  TOKEN_BINARY_SERIALIZED = 50

  #
  # Limited Object Stream Types
  #
  class ObjectStateFormatter < BinData::Record
    # see: https://github.com/microsoft/referencesource/blob/3b1eaf5203992df69de44c783a3eda37d3d4cd10/System.Web/UI/ObjectStateFormatter.cs
    endian                 :little
    default_parameter      marker_format: 0xff
    default_parameter      marker_version: 1
    hide                   :marker_format,  :marker_version
    uint8                  :marker_format,  initial_value: :marker_format
    uint8                  :marker_version, initial_value: :marker_version
    uint8                  :token
  end

  def self.generate(stream)
    stream = stream.to_binary_s
    formatted  = ObjectStateFormatter.new(token: TOKEN_BINARY_SERIALIZED).to_binary_s
    formatted << DotNetDeserialization.encode_7bit_int(stream.length)
    formatted << stream
  end

end
end
end
end
end
