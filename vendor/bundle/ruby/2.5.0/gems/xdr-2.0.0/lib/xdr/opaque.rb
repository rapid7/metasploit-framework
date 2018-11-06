class XDR::Opaque
  include XDR::Concerns::ConvertsToXDR
  include XDR::Concerns::StringConverter

  singleton_class.send(:alias_method, :[], :new)

  def initialize(length)
    @length = length
    @padding = padding_for length
  end

  def read(io)
    # read and return @length bytes
    # throw away @padding bytes
    read_bytes(io, @length).tap{ read_bytes(io, @padding) }
  end

  def write(val,io)
    length = val.bytesize
    
    if val.length != @length
      raise XDR::WriteError, "Value length is #{length}, must be #{@length}" 
    end

    io.write val
    io.write "\x00" * @padding
  end
end