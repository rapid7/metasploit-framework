module XDR::Concerns::FloatConverter
  def valid?(val)
    val.is_a?(Float)
  end
end