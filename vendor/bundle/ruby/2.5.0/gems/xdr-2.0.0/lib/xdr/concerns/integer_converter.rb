module XDR::Concerns::IntegerConverter
  def valid?(val)
    val.is_a?(Integer)
  end
end