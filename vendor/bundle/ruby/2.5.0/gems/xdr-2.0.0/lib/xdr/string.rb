class XDR::String
  include XDR::Concerns::ConvertsToXDR
  include XDR::Concerns::StringConverter

  singleton_class.send(:alias_method, :[], :new)
  
  def initialize(length=XDR::MAX_SIZE)
    @length = length
  end

  def write(val, io)
    length = val.bytesize

    if length > @length
      raise XDR::WriteError, "Value length #{length} exceeds max #{@length}"
    end

    XDR::Int.write(length, io)
    io.write val
    io.write "\x00" * padding_for(length)
  end

  def read(io)
    length = XDR::Int.read(io)

    if length > @length
      raise XDR::ReadError, "String length #{length} is greater than max"
    end

    padding = padding_for length

    # read and return length bytes
    # throw away padding bytes
    read_bytes(io, length).tap{ read_bytes(io, padding) }
  end
end