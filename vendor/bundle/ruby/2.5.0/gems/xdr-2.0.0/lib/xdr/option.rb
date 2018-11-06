class XDR::Option
  include XDR::Concerns::ConvertsToXDR

  singleton_class.send(:alias_method, :[], :new)

  attr_reader :child_type

  def initialize(child_type)
    #TODO, raise an error if child_type is not ConvertToXDR
    @child_type = child_type
  end

  def write(val, io)
    if val.present?
      XDR::Bool.write(true, io)
      @child_type.write(val, io)
    else
      XDR::Bool.write(false, io)
    end
  end

  def read(io)
    present = XDR::Bool.read(io)
    @child_type.read(io) if present
  end

  def valid?(val)
    val.nil? || @child_type.valid?(val)
  end
end