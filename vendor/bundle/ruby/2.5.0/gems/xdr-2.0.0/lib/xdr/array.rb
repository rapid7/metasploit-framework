class XDR::Array
  include XDR::Concerns::ConvertsToXDR
  include XDR::Concerns::ArrayConverter

  singleton_class.send(:alias_method, :[], :new)

  def initialize(child_type, length)
    @child_type = child_type
    @length     = length
  end

  def write(val, io)
    raise XDR::WriteError, "val is not array" unless val.is_a?(Array)
    raise XDR::WriteError, "array must be #{@length} long, was #{val.length}" if val.length != @length

    @length.times do |i|
      @child_type.write val[i], io
    end
  end

  def read(io)
    @length.times.map{ @child_type.read(io) }
  end

  def valid?(val)
    super(val) && val.length == @length
  end
end