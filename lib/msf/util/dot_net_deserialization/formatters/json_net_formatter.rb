module Msf
module Util
module DotNetDeserialization
module Formatters
module JsonNetFormatter

  def self.generate(stream)
    unless stream.is_a?(GadgetChains::ObjectDataProvider)
      raise ::NotImplementedError, 'Stream is not supported by this formatter'
    end

    stream.object.to_json
  end

end
end
end
end
end
