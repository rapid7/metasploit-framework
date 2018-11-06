class XDR::VarArray
  include XDR::Concerns::ConvertsToXDR
  include XDR::Concerns::ArrayConverter

  singleton_class.send(:alias_method, :[], :new)

  def initialize(child_type, length=XDR::MAX_SIZE)
    @child_type   = child_type
    @length = length
  end

  def write(val, io)
    length = val.length

    if length > @length
      raise XDR::WriteError, "Value length #{length} exceeds max #{@length}"
    end

    XDR::Int.write(length, io)
    val.each do |member|
      @child_type.write member, io
    end
  end

  def read(io)
    length = XDR::Int.read(io)

    if length > @length
      raise XDR::ReadError, "VarArray length #{length} is greater than max #{@length}"
    end

    length.times.map{ @child_type.read(io) }
  end

  def valid?(val)
    super(val) && val.length <= @length
  end
end