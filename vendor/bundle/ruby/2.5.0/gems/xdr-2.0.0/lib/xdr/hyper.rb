module XDR::Hyper
  extend XDR::Concerns::ConvertsToXDR
  extend XDR::Concerns::IntegerConverter

  def self.write(val, io)
    raise XDR::WriteError, "val is not Integer" unless val.is_a?(Integer)
    # TODO: check bounds
    io.write [val].pack("q>")
  end

  def self.read(io)
    read_bytes(io, 8).unpack("q>").first
  end
end