module XDR::Double
  extend XDR::Concerns::ConvertsToXDR
  extend XDR::Concerns::FloatConverter

  def self.write(val, io)
    raise XDR::WriteError unless valid?(val)
    io.write [val].pack("G")
  end

  def self.read(io)
    read_bytes(io, 8).unpack("G").first
  end

end