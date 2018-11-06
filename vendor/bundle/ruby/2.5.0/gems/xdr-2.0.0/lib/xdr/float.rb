module XDR::Float
  extend XDR::Concerns::ConvertsToXDR
  extend XDR::Concerns::FloatConverter

  def self.write(val, io)
    raise XDR::WriteError unless val.is_a?(Float)
    io.write [val].pack("g")
  end

  def self.read(io)
    read_bytes(io, 4).unpack("g").first
  end

end