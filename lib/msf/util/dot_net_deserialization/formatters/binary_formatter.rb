module Msf
module Util
module DotNetDeserialization
module Formatters
module BinaryFormatter

  def self.generate(stream)
    unless stream.is_a?(Types::SerializedStream)
      raise ::NotImplementedError, 'Stream is not supported by this formatter'
    end

    stream.to_binary_s
  end

end
end
end
end
end
